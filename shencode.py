import os

import utils.arg as arg
from utils.helper import nstate as nstate
from utils.helper import FileCheck
import utils.extract as extract
import utils.formatout as formatout
import utils.hashes as hashes
if os.name == 'nt':
  import utils.injection as injection
import utils.msf as msf
import encoder.aes as aes
import encoder.byteswap as byteswap
import encoder.xorpoly as xorpoly
import encoder.xor as xor
import obfuscator.qrcode as qrcode
import obfuscator.rolhash as rolhash
import obfuscator.uuid as uuid

Version = '0.5.2'

# make sure your metasploit binary folder is in your PATH variable
if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  
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

  ##########################
  ### BEGIN INIT SECTION ###
  ##########################

  arg.CreateMainParser()
  aes.aes_encoder.init()
  byteswap.xor.init()
  extract.extract_shellcode.init()
  formatout.format.init()
  if os.name == 'nt':
    injection.inject.init()
  msf.msfvenom.init()
  qrcode.qrcode_obfuscator.init()
  if os.name == 'nt':
    rolhash.ror2rol_obfuscator.init()
  uuid.uuid_obfuscator.init()
  xorpoly.xor.init()
  xor.xor_encoder.init()
  arguments = arg.ParseArgs(command_line)

  ##########################
  #### END INIT SECTION ####
  ##########################
  

  # MAIN

  if arguments.command == 'msfvenom':
    print(f"{nstate.OKBLUE} create payload")
    cs = msf.msfvenom
    cs.CreateShellcodeEx(msfvenom_path, arguments.cmd)

  ### Check Code ###
  elif arguments.command == 'xorpoly':
    poly = xorpoly.xor(arguments.input, arguments.output, b'', 'tpl\\xor-stub.tpl', arguments.key)
    #xorpoly.xor.Input_File = arguments.input
    #xorpoly.xor.SetInputFile(arguments.input)
    #xorpoly.xor.XOR_Key = arguments.key
    #xorpoly.xor.Output_File = arguments.output
    #xorpoly.xor.Template_File = 'tpl\\xor-stub.tpl'
    #filecheck, outstrings = FileCheck.CheckSourceFile(xorpoly.xor.Input_File, 'XOR-POLY')
    filecheck, outstrings = FileCheck.CheckSourceFile(poly.input_file, 'XOR-POLY')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      with open(arguments.input, "rb") as file:
        shellcode = file.read()
    else:
      exit()
    modified_shellcode = xor.xor_encoder.xor_crypt_bytes(shellcode, int(arguments.key))
    outputfile = 'xor.tmp'
    with open(outputfile, 'wb') as file:
      file.write(modified_shellcode)
    filecheck, outstrings = FileCheck.CheckWrittenFile(outputfile, 'XOR-POLY')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      poly.input_file = outputfile
      #xorpoly.xor.Input_File = outputfile
      # poly.LoadHeader()
      # poly.AppendShellcode()
      # poly.shellcode = poly.replace_bytes_at_offset(poly.Shellcode, 5, poly.XOR_Key)
      # poly.WriteToFile()
      poly.process()
      #xorpoly.xor.process()
    else:
      exit()

  elif arguments.command == 'byteswap':
    swapper = byteswap.xor(arguments.input, arguments.output, 'tpl\\byteswap-short.tpl', arguments.key)
    # byteswap.xor.Input_File = arguments.input
    # byteswap.xor.XOR_Key = arguments.key
    # byteswap.xor.Output_File = arguments.output
    # byteswap.xor.Template_File = 'tpl\\byteswap-short.tpl'
    filecheck, outstrings = FileCheck.CheckSourceFile(swapper.input_file, 'XOR-SWAP')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      with open(swapper.input_file, "rb") as file:
        shellcode = file.read()
    else:
      exit()
    swapper.process()
    #outputfile = swapper.output_file
    filecheck, outstrings = FileCheck.CheckWrittenFile(swapper.output_file, 'XOR-SWAP')
    for string in outstrings:
      print(f'{string}')

  elif arguments.command == 'aesenc':
    if arguments.debug:
      aes.aes_encoder.debug()
    else:
      print(f'{nstate.OKBLUE} [AES] Module')
      aes.aes_encoder.Input_File = arguments.input
      aes.aes_encoder.Output_File = arguments.output
      PasswordBytes = arguments.key
      aes.aes_encoder.Password = PasswordBytes.encode('utf-8')
      if arguments.mode == 'encode':
        print(f'{nstate.OKBLUE} [AES] ENCRYPT')
        filecheck, outstrings = FileCheck.CheckSourceFile(aes.aes_encoder.Input_File, 'AES-ENC')
        for string in outstrings:
          print(f'{string}')
        if filecheck:
          aes.aes_encoder.encode()
          filecheck, outstrings = FileCheck.CheckWrittenFile(aes.aes_encoder.Output_File, 'AES-ENC')
          for string in outstrings:
            print(f'{string}')
        else:
          exit()
      elif arguments.mode == 'decode':
        print(f'{nstate.OKBLUE} [AES] DECRYPT')
        filecheck, outstrings = FileCheck.CheckSourceFile(aes.aes_encoder.Input_File, 'AES-DEC')
        for string in outstrings:
          print(f'{string}')
        if filecheck:
          aes.aes_encoder.decode()
          filecheck, outstrings = FileCheck.CheckWrittenFile(aes.aes_encoder.Output_File, 'AES-DEC')
          for string in outstrings:
            print(f'{string}')
        else:
          exit()

  elif arguments.command == 'uuid':
      short_fn = os.path.basename(arguments.input)
      uuid_obf = uuid.uuid_obfuscator(arguments.input, '', '', 0)
      print(f"{nstate.OKBLUE} try to open file")
      if uuid_obf.open_file(uuid_obf.input_file):
        print(f"{nstate.OKGREEN} reading {short_fn} successful!")
      else:
        print(f"{nstate.FAIL} file not found, exit")
      print(f"{nstate.OKBLUE} try to generate UUIDs")  
      print(uuid_obf.CreateVar())

  elif arguments.command == 'qrcode':
    qr = qrcode.qrcode_obfuscator(arguments.input, arguments.output, '')
    filecheck, outstrings = FileCheck.CheckSourceFile(qr.input_file, 'OBF-QRC')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      qr.open_file()
      qr.process()
    else:
      exit()
    filecheck, outstrings = FileCheck.CheckWrittenFile(qr.output_file, 'OBF-QRC')
    for string in outstrings:
      print(f'{string}')

  elif arguments.command == 'formatout':
      filename = arguments.input
      OutputFormat = arguments.syntax
      lines = arguments.lines
      formatout.format.no_line_break = arguments.no_break
      print(filename)
      print(f"{nstate.OKBLUE} processing shellcode format... NoLineBreak: {formatout.format.no_line_break}")
      fo = formatout.format
      scFormat = fo.process(filename,OutputFormat,lines)
      print(scFormat)
      if arguments.write:
        fo.FileManipulation.WriteToTemplate(arguments.write, scFormat)
        print(f"{nstate.OKGREEN} Output written in buf {arguments.write}")
      print(f"{nstate.OKGREEN} DONE!")

  elif arguments.command == 'ror2rol':
      ror_key = int(arguments.key)
      if (ror_key < 32) or (ror_key > 255):
        print(f"{nstate.FAIL} Key must be between 33 and 255")
        exit()
      rolhash.ror2rol_obfuscator.process(arguments.input, arguments.output, arguments.key)

  elif arguments.command == 'xorenc':
      xor_encoder = xor.xor_encoder(arguments.input, arguments.output, arguments.key)
      print(f"{nstate.OKBLUE} Reading shellcode")
      filecheck, outstrings = FileCheck.CheckSourceFile(xor_encoder.input_file, 'XOR-ENC')
      for strings in outstrings:
        print(f'{strings}')
      if filecheck:
        with open(arguments.input, "rb") as file:
          shellcode = file.read()
      else:
        exit()
      modified_shellcode = xor_encoder.xor_crypt_bytes(shellcode, int(xor_encoder.xor_key))
      #outputfile = arguments.output
      with open(xor_encoder.output_file, 'wb') as file:
        file.write(modified_shellcode)
      filecheck, outstrings = FileCheck.CheckWrittenFile(xor_encoder.output_file, 'XOR-ENC')
      for strings in outstrings:
        print(f'{strings}')
      if not filecheck:
        exit()

  elif arguments.command == 'inject':
    print(f"{nstate.OKBLUE} Reading shellcode")
    filename = arguments.input
    try: 
      with open(filename, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
        print(f"{nstate.FAIL} File not found or cannot be opened.")
        exit()
    inject = injection.inject
    inject.Shellcode = shellcode
    inject.StartProcess = arguments.start
    inject.Target_Process = arguments.process
    inject.start_injection()

  elif arguments.command == 'extract':
    ext = extract.extract_shellcode(arguments.input, arguments.output, arguments.start_offset, arguments.end_offset)
    filecheck, outstrings = FileCheck.CheckSourceFile(ext.input_file, 'XTRACT')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      ext.process()
    else:
      exit()
    filecheck, outstrings = FileCheck.CheckSourceFile(ext.output_file, 'XTRACT')
    for string in outstrings:
      print(f'{string}')

  elif arguments.version:
    print(f'ShenCode {Version}')

if __name__ == "__main__":
  main()
