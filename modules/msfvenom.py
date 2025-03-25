########################################################
### MSFVenom Module
### Status: untested
########################################################

#import utils.arg
from utils.helper import nstate
#from utils.helper import GetFileHash, CheckFile
import subprocess

CATEGORY = 'core'

def register_arguments(parser):
      parser.add_argument('-c', '--cmd', help='msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"')

class module:
  Author        = 'psycore8'
  Description   = 'Generate payloads with metasploit'
  Version       = '2.1.1'
  DisplayName   = 'MSFGEN'
  Args          = []
  
  def __init__(self, command_line, msfvenom_path):
    self.command_line = command_line
    self.msfvenom_path = msfvenom_path

  def msg(self, message_type, ErrorExit=False):
      messages = {
          'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
          'pre.msg'       : f'{nstate.s_note} Creating payload...',
          'process'       : f'{nstate.s_note}{self.Args}',
          'post.done'     : f'{nstate.s_ok} DONE!',
      }
      print(messages.get(message_type, 'Unknown message type'))
      if ErrorExit:
          exit()
  
  def CreateShellcodeEx(self):
    self.msg('pre.head')
    msf_args = self.command_line.split()
    msf_args.insert(0, self.msfvenom_path)
    self.Args = msf_args
    self.msg('process')
    subprocess.run(msf_args)
    self.msg('post.done')
    return True
  
  def process(self):
     self.CreateShellcodeEx()
