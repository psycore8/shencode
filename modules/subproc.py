########################################################
### ShenCode Module
###
### Name: Subproc Module
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
import subprocess

CATEGORY    = 'core'
DESCRIPTION = 'Execute a subprocess'

cs = ConsoleStyles()

arglist = {
    'command_line':         { 'value': [], 'desc': 'Command line to execute' }
}

def register_arguments(parser):
    parser.add_argument('-c', '--command-line', default=[], help=arglist['command_line']['desc'])

class module:
    Author =      'psycore8'
    Version =     '0.9.0'
    DisplayName = 'SUBPR0CESS'
    hash = ''
    data_size = 0
    shell_path = '::core::subproc'

    def __init__(self, command_line):
        self.command_line = command_line

    def run_subprocess(self):
        subprocess.run(self.command_line)

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        result = subprocess.run(self.command_line).returncode
        
        if result != 0:
            cs.print(f'Error during processing: {result} {self.command_line}', cs.state_fail)
        cs.print('Subprocess executed', cs.state_ok)
        cs.print('DONE!', cs.state_ok)

            