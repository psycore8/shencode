########################################################
### MSFVenom Module
### Status: cleaned, 083
###
########################################################

from utils.helper import nstate
from utils.const import msfvenom_path
import subprocess

CATEGORY    = 'payload'
DESCRIPTION = 'Generate payloads with msfvenom'

def register_arguments(parser):
      parser.add_argument('-c', '--command-line', help='msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"')

class module:
  Author        = 'psycore8'
  Version       = '2.1.3'
  DisplayName   = 'MSF-VENOM'
  Args          = []
  
  def __init__(self, command_line):
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
