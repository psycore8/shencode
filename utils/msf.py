import utils.arg
import subprocess

class msfvenom:
  Author = 'psycore8'
  Description = 'Generate payloads with metasploit'
  Version = '1.1.0'

  def __init__(self, command_line):
    self.command_line = command_line

  def init():
    spName = 'msfvenom'
    spArgList = [
      ['-c', '--cmd', '', '', 'msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"']
    ]
    utils.arg.CreateSubParser(spName, msfvenom.Description, spArgList)
  
  def CreateShellcodeEx(self, msfvenom_path):
    msf_args = self.command_line.split()
    msf_args.insert(0, msfvenom_path)
    print(f'Argument List: {msf_args}')
    subprocess.run(msf_args)
    return True
