########################################################
### MSFVenom Module
### Status: migrated 085
###
########################################################

from utils.style import *
from utils.const import msfvenom_path
import subprocess

CATEGORY    = 'payload'
DESCRIPTION = 'Generate payloads with msfvenom'

arglist = {
   'command_line':      { 'value': None, 'desc': 'Msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"' }
}

def register_arguments(parser):
      parser.add_argument('-c', '--command-line', help=arglist['command_line']['desc'])

class module:
  Author        = 'psycore8'
  Version       = '2.1.5'
  DisplayName   = 'MSF-VENOM'
  Args          = []
  shell_path    = '::payload::msfvenom'

  def __init__(self, command_line):
    self.command_line = command_line
    self.msfvenom_path = msfvenom_path

  def msg(self, message_type, ErrorExit=False):
      messages = {
          'pre.head'      : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
          'pre.msg'       : f'{s_note} Creating payload...',
          'process'       : f'{s_note}{self.Args}',
          'post.done'     : f'{s_ok} DONE!',
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
