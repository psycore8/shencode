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
import modules.info as info
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
# if you want a static banner, specify it here
banner = -1

print(f"{nstate.HEADER}")
# if banner > 0:
#   print(f'{utils.header.get_header(banner)}')
#   exit()
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
    cs = msf.msfvenom(arguments.cmd, msfvenom_path)
    cs.process()

  elif arguments.command == 'output':
    mod = output.format_shellcode(arguments.input, arguments.syntax, arguments.bytes_per_row, arguments.decimal, arguments.lines, arguments.no_line_break, arguments.output)
    mod.process()

  elif arguments.command == 'meterpreter':
    stager = meterpreter.stage(arguments.remote_host, arguments.port, arguments.timeout, arguments.arch, arguments.sleep)
    stager.process()

  elif arguments.command == 'sliver':
    stager = sliver.stage(arguments.remote_host, arguments.port, arguments.sleep, arguments.aes, arguments.aes_key, arguments.aes_iv, arguments.compression, arguments.headers)
    stager.process()

  elif arguments.command == 'bytebert':
    bb = bytebert.bb_encoder(arguments.input, arguments.output, arguments.variable_padding)
    bb.process()

  elif arguments.command == 'xorpoly':
    poly = xorpoly.xor(arguments.input, arguments.output, b'', b'', f'{tpl_path}xor-stub.tpl', arguments.key)
    poly.process()

  elif arguments.command == 'byteswap':
    swapper = byteswap.xor(arguments.input, arguments.output, f'{tpl_path}byteswap-short.tpl', arguments.key)
    swapper.process()

  elif arguments.command == 'aes':
    aes_enc = aes.aes_encoder(arguments.mode, arguments.input, arguments.output, arguments.key, b'')
    aes_enc.process()

  elif arguments.command == 'uuid':
      uuid_obf = uuid.uuid_obfuscator(arguments.input, '', '', 0)
      uuid_obf.process()

  elif arguments.command == 'feed':
    feed_obf = feed.feed_obfuscator(arguments.input, arguments.output, arguments.uri, arguments.reassemble)
    feed_obf.process()

  elif arguments.command == 'qrcode':
    qr = qrcode.qrcode_obfuscator(arguments.input, arguments.output, '')
    qr.process()

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

  elif arguments.command == 'injection':
    code_injection = injection.inject(arguments.input, arguments.start, arguments.process, '', arguments.resume_thread, arguments.virtual_protect)
    code_injection.process()

  elif arguments.command == 'extract':
    ext = extract.extract_shellcode(arguments.input, arguments.output, arguments.start_offset, arguments.end_offset)
    ext.process()

  elif arguments.command == 'info':
    inf = info.develop(Version, 'modules', arguments.modlist)
    inf.process()

  elif arguments.version:
    print(f'ShenCode {Version}')

if __name__ == "__main__":
    main()
