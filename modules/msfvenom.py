########################################################
### ShenCode Module
###
### Name: MSF-Venom
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.const import msfvenom_path
import subprocess

CATEGORY    = 'payload'
DESCRIPTION = 'Generate payloads with msfvenom'

cs = ConsoleStyles()

arglist = {
   'command_line':      { 'value': None, 'desc': 'Msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"' },
   'output':            { 'value': None, 'desc': 'Output file to generate (will be appended to command line with -o filename)' }
}

def register_arguments(parser):
      parser.add_argument('-c', '--command-line', help=arglist['command_line']['desc'])
      parser.add_argument('-o', '--output', help=arglist['output']['desc'])

class module:
  Author        = 'psycore8'
  Version       = '0.9.0'
  DisplayName   = 'MSF-VENOM'
  Args          = []
  shell_path    = '::payload::msfvenom'

  def __init__(self, command_line, output):
    self.command_line = command_line
    self.msfvenom_path = msfvenom_path
    self.output = output
  
  def CreateShellcodeEx(self):
    cs.module_header(self.DisplayName, self.Version)
    msf_args = self.command_line.split()
    msf_args.insert(0, self.msfvenom_path)
    msf_args.append('-o')
    msf_args.append(self.output)
    self.Args = msf_args
    cs.print(f'{self.Args}', cs.state_note)
    subprocess.run(msf_args)
    cs.action_save_file2(self.output)
    cs.print('DONE!', cs.state_ok)
    return True
  
  def process(self):
     self.CreateShellcodeEx()
