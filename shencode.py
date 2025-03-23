import os

from utils.args import parse_arguments
from utils.helper import nstate as nstate
from utils.helper import FileCheck
#import utils.hashes as hashes
import utils.header
import utils.helper
import importlib

# import modules.aes as aes
# import modules.bytebert as bytebert
# import modules.byteswap as byteswap
# import modules.extract as extract
# import modules.feed as feed
# import modules.formatout as formatout

# import modules.info as info
# #import modules.interactive as interactive
# import modules.msfvenom as msf
# import modules.output as output
# import modules.qrcode as qrcode
# import modules.task as task
# import modules.uuid as uuid
# import modules.xor as xor
# import modules.xorpoly as xorpoly
# if os.name == 'nt':
#   import modules.psoverwrite as psoverwrite
#   import modules.dll as dll
#   import modules.injection as injection
#   import modules.meterpreter as meterpreter
#   import modules.ntinjection as ntinjection
#   import modules.rolhash as rolhash
#   import modules.sliver as sliver


#import modules.power as power

Version = '0.8.1'
# if you want a static banner, specify it here
banner = -1

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
  argd = arguments.__dict__
  #mod = argd['command']
  mod = importlib.import_module(f'modules.{argd['command']}')
  del argd['module']
  del argd['command']
  class_init = mod.module(**argd)
  class_init.process()
  # if arguments.command == 'msfvenom':
  #   cs = msf.module(arguments.cmd, msfvenom_path)
  #   cs.process()

  # elif arguments.command == 'output':
  #   mod = output.module(arguments.input, arguments.syntax, arguments.bytes_per_row, arguments.decimal, arguments.lines, arguments.no_line_break, arguments.output)
  #   mod.process()

  # elif arguments.command == 'meterpreter':
  #   stager = meterpreter.module(arguments.remote_host, arguments.port, arguments.timeout, arguments.arch, arguments.sleep)
  #   stager.process()

  # elif arguments.command == 'sliver':
  #   #print(f'{arguments.aes}')
  #   stager = sliver.module(arguments.remote_host, arguments.port, arguments.sleep, arguments.aes[0], arguments.aes[1], arguments.compression, arguments.headers, arguments.relay)
  #   stager.process()

  # elif arguments.command == 'bytebert':
  #   bb = bytebert.module(arguments.input, arguments.output, arguments.variable_padding)
  #   bb.process()

  # elif arguments.command == 'xorpoly':
  #   poly = xorpoly.module(arguments.input, arguments.output, b'', b'', f'{tpl_path}xor-stub.tpl', arguments.key, arguments.relay)
  #   poly.process()

  # elif arguments.command == 'psoverwrite':
  #   ow = psoverwrite.module(arguments.target, arguments.payload, arguments.nocfg) #xorpoly.xor(arguments.input, arguments.output, b'', b'', f'{tpl_path}xor-stub.tpl', arguments.key)
  #   ow.process()

  # elif arguments.command == 'byteswap':
  #   swapper = byteswap.module(arguments.input, arguments.output, f'{tpl_path}byteswap-short.tpl', arguments.key)
  #   swapper.process()

  # elif arguments.command == 'dll':
  #   dll_inj = dll.module(arguments.input, arguments.process, arguments.start_process)
  #   dll_inj.process()

  # elif arguments.command == 'aes':
  #   aes_enc = aes.module(arguments.mode, arguments.input, arguments.output, arguments.key, b'')
  #   aes_enc.process()

  # elif arguments.command == 'uuid':
  #     uuid_obf = uuid.module(arguments.input, '', '', 0)
  #     uuid_obf.process()

  # elif arguments.command == 'feed':
  #   feed_obf = feed.module(arguments.input, arguments.output, arguments.uri, arguments.reassemble)
  #   feed_obf.process()

  # elif arguments.command == 'qrcode':
  #   qr = qrcode.module(arguments.input, arguments.output, '')
  #   qr.process()

  # elif arguments.command == 'formatout':
  #     fout = formatout.format(arguments.input, arguments.syntax, arguments.lines, arguments.no_break, arguments.write, arguments.bytes_per_row)
  #     print(fout.input_file)
  #     print(f"{nstate.OKBLUE} processing shellcode format... NoLineBreak: {fout.no_break}")
  #     scFormat = fout.process()
  #     print(scFormat)
  #     if arguments.write:
  #       fout.WriteToTemplate(fout.write_out, scFormat)
  #       print(f"{nstate.OKGREEN} Output written in buf {fout.write_out}")
  #     print(f"{nstate.OKGREEN} DONE!")

  # elif arguments.command == 'interactive':
  #   ia = interactive.interactive_mode('modules')
  #   ia.process()

  # elif arguments.command == 'rolhash':
  #     r2l = rolhash.ror2rol_obfuscator(arguments.input, arguments.output, arguments.key)
  #     filecheck, outstrings = FileCheck.CheckSourceFile(r2l.input_file, 'ROR2ROL')
  #     for string in outstrings:
  #       print(f'{string}')
  #     if filecheck:
  #       ror_key = int(r2l.key)
  #       if (ror_key < 32) or (ror_key > 255):
  #         print(f"{nstate.FAIL} Key must be between 33 and 255")
  #         exit()
  #       r2l.process()
  #     else:
  #       exit()
  #     filecheck, outstrings = FileCheck.CheckWrittenFile(r2l.output_file, 'ROR2ROL')
  #     for string in outstrings:
  #       print(f'{string}')

  # elif arguments.command == 'xor':
  #     xor_encoder = xor.module(arguments.input, arguments.output, arguments.key, arguments.verbose, arguments.mode, arguments.relay)
  #     xor_encoder.process()

  # elif arguments.command == 'injection':
  #   code_injection = injection.module(arguments.input, arguments.start, arguments.process, '', arguments.resume_thread, arguments.virtual_protect)
  #   code_injection.process()

  # elif arguments.command == 'ntinjection':
  #   code_injection = ntinjection.module(arguments.input, arguments.start, arguments.process, '')
  #   code_injection.process()

  # elif arguments.command == 'extract':
  #   ext = extract.module(arguments.input, arguments.output, arguments.extract_range, arguments.start_offset, arguments.end_offset)
  #   ext.process()

  # elif arguments.command == 'info':
  #   inf = info.module(Version, 'modules', arguments.modlist)
  #   inf.process()

  # elif arguments.command == 'task':
  #   ta = task.module(arguments.input) #info.develop(Version, 'modules', arguments.modlist)
  #   ta.process()

if __name__ == "__main__":
  main()

  # elif arguments.version:
  #   print(f'ShenCode {Version}')
