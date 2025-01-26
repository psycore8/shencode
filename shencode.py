import os

import utils.arg as arg
from utils.helper import nstate as nstate
from utils.helper import FileCheck
import utils.extract as extract
import utils.formatout as formatout
import utils.hashes as hashes
import utils.header
import utils.meterpreter as meterpreter
if os.name == 'nt':
  import utils.injection as injection
import utils.msf as msf
import encoder.aes as aes
import encoder.byteswap as byteswap
import encoder.xorpoly as xorpoly
import encoder.xor as xor
import obfuscator.feed as feed
import obfuscator.qrcode as qrcode
import obfuscator.rolhash as rolhash
import obfuscator.uuid as uuid

Version = '0.6.2'

# make sure your metasploit binary folder is in your PATH variable
if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  tpl_path = 'tpl/'
  
def main(command_line=None):
  print(f"{nstate.HEADER}")
  print(f'{utils.header.get_header()}')
  print(f'Version {Version} by psycore8 -{nstate.ENDC} {nstate.TextLink('https://www.nosociety.de')}')


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
  meterpreter.stager.init()
  msf.msfvenom.init()
  feed.feed_obfuscator.init()
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
    cs = msf.msfvenom(arguments.cmd)
    cs.CreateShellcodeEx(msfvenom_path)

  elif arguments.command == 'msfstager':
    stager = meterpreter.stager(arguments.remote_host, arguments.port, arguments.timeout, arguments.arch)
    stager.process()


  elif arguments.command == 'xorpoly':
    poly = xorpoly.xor(arguments.input, arguments.output, b'', b'', f'{tpl_path}xor-stub.tpl', arguments.key)
    xor_enc = xor.xor_encoder('', '', 0)
    filecheck, outstrings = FileCheck.CheckSourceFile(poly.input_file, 'XOR-POLY')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      with open(poly.input_file, "rb") as file:
        shellcode = file.read()
    else:
      exit()
    poly.xored_shellcode = xor_enc.xor_crypt_bytes(shellcode, int(poly.xor_key))
    poly.process()
    filecheck, outstrings = FileCheck.CheckWrittenFile(poly.output_file, 'XOR-POLY')
    for string in outstrings:
      print(f'{string}')

  elif arguments.command == 'byteswap':
    swapper = byteswap.xor(arguments.input, arguments.output, f'{tpl_path}byteswap-short.tpl', arguments.key)
    filecheck, outstrings = FileCheck.CheckSourceFile(swapper.input_file, 'XOR-SWAP')
    for string in outstrings:
      print(f'{string}')
    if filecheck:
      with open(swapper.input_file, "rb") as file:
        shellcode = file.read()
    else:
      exit()
    swapper.process()
    filecheck, outstrings = FileCheck.CheckWrittenFile(swapper.output_file, 'XOR-SWAP')
    for string in outstrings:
      print(f'{string}')

  elif arguments.command == 'aesenc':
    aes_enc = aes.aes_encoder(arguments.mode, arguments.input, arguments.output, arguments.key, b'')
    print(f'{nstate.OKBLUE} [AES] Module')
    aes_enc.key = aes_enc.key.encode('utf-8')
    if aes_enc.mode == 'encode':
      print(f'{nstate.OKBLUE} [AES] ENCRYPT')
      filecheck, outstrings = FileCheck.CheckSourceFile(aes_enc.input_file, 'AES-ENC')
      for string in outstrings:
        print(f'{string}')
      if filecheck:
        aes_enc.encode()
        filecheck, outstrings = FileCheck.CheckWrittenFile(aes_enc.output_file, 'AES-ENC')
        for string in outstrings:
          print(f'{string}')
      else:
        exit()
    elif aes_enc.mode == 'decode':
      print(f'{nstate.OKBLUE} [AES] DECRYPT')
      filecheck, outstrings = FileCheck.CheckSourceFile(aes_enc.input_file, 'AES-DEC')
      for string in outstrings:
        print(f'{string}')
      if filecheck:
        aes_enc.decode()
        filecheck, outstrings = FileCheck.CheckWrittenFile(aes_enc.output_file, 'AES-DEC')
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

  elif arguments.command == 'feed':
    feed_obf = feed.feed_obfuscator(arguments.input, arguments.output, arguments.uri)

    if feed_obf.uri:
      feed_obf.reassemble_shellcode()
      filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.output_file, 'OBF-RSS')
      for string in outstrings:
        print(string)
      exit()
    filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.input_file, 'OBF-RSS')
    for string in outstrings:
      print(string)
    if filecheck:
      feed_obf.open_file()
      feed_obf.convert_bytes_to_fake_id()
      feed_obf.generate_feed()
    else:
      exit()
    filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.output_file, 'OBF-RSS')
    for string in outstrings:
      print(string)

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
      fout = formatout.format(arguments.input, arguments.syntax, arguments.lines, arguments.no_break, arguments.write)
      print(fout.input_file)
      print(f"{nstate.OKBLUE} processing shellcode format... NoLineBreak: {fout.no_break}")
      scFormat = fout.process()
      print(scFormat)
      if arguments.write:
        fout.WriteToTemplate(fout.write_out, scFormat)
        print(f"{nstate.OKGREEN} Output written in buf {fout.write_out}")
      print(f"{nstate.OKGREEN} DONE!")

  elif arguments.command == 'ror2rol':
      r2l = rolhash.ror2rol_obfuscator(arguments.input, arguments.output, arguments.key)
      filecheck, outstrings = FileCheck.CheckSourceFile(r2l.input_file, 'ROR2ROL')
      for string in outstrings:
        print(f'{string}')
      if filecheck:
        ror_key = int(r2l.key)
        if (ror_key < 32) or (ror_key > 255):
          print(f"{nstate.FAIL} Key must be between 33 and 255")
          exit()
        r2l.process()
      else:
        exit()
      filecheck, outstrings = FileCheck.CheckWrittenFile(r2l.output_file, 'ROR2ROL')
      for string in outstrings:
        print(f'{string}')

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
      with open(xor_encoder.output_file, 'wb') as file:
        file.write(modified_shellcode)
      filecheck, outstrings = FileCheck.CheckWrittenFile(xor_encoder.output_file, 'XOR-ENC')
      for strings in outstrings:
        print(f'{strings}')
      if not filecheck:
        exit()

  elif arguments.command == 'inject':
    code_injection = injection.inject(arguments.input, arguments.start, arguments.process, '')
    print(f"{nstate.OKBLUE} Reading shellcode")
    filecheck, outstrings = FileCheck.CheckSourceFile(code_injection.input_file, 'iNJECT')
    for strings in outstrings:
      print(f'{strings}')
    if filecheck:
      with open(code_injection.input_file, "rb") as file:
        code_injection.shellcode = file.read()
        code_injection.start_injection()

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
