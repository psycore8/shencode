import utils.arg
import subprocess

class msfvenom:
  Author = 'psycore8'
  Description = 'Generate payloads with metasploit'
  Version = '1.0.0'

  def init():
    spName = 'msfvenom'
    spArgList = [
      ['-c', '--cmd', '', '', 'msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"']
    ]
    utils.arg.CreateSubParser(spName, msfvenom.Description, spArgList)
  
  def CreateShellcodeEx(msfvenom_path, msf_command):
    msf_args = msf_command.split()
    msf_args.insert(0, msfvenom_path)
    print(f'Argument List: {msf_args}')
    subprocess.run(msf_args)
    return True
