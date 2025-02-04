#import utils.arg
import subprocess

CATEGORY = 'core'

def register_arguments(parser):
      parser.add_argument('-c', '--cmd', help='msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"')

class msfvenom:

  Author = 'psycore8'
  Description = 'Generate payloads with metasploit'
  Version = '2.0.0'
  
  def __init__(self, command_line):
    self.command_line = command_line
  
  def CreateShellcodeEx(self, msfvenom_path):
    msf_args = self.command_line.split()
    msf_args.insert(0, msfvenom_path)
    print(f'Argument List: {msf_args}')
    subprocess.run(msf_args)
    return True
