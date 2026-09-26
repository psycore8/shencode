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

css = ConsoleStyles()
cs_print = css.console_print()

arglist = {
    'command_line':         { 'value': [], 'desc': 'Command line to execute' }
}

def register_arguments(parser):
    parser.add_argument('-c', '--command-line', default=[], help=arglist['command_line']['desc'])

class module:
    Author =      'psycore8'
    Version =     '1.0.1'
    DisplayName = 'SUBPR0CESS'
    hash = ''
    data_size = 0
    shell_path = '::core::subproc'

    def __init__(self, command_line):
        self.command_line = command_line

    def run_subprocess(self):
        subprocess.run(self.command_line)

    def process(self):
        css.module_header(self.DisplayName, self.Version)
        result = subprocess.run(self.command_line).returncode
        
        if result != 0:
            cs_print.error(f'Error during processing: {result} {self.command_line}')
        cs_print.ok('Subprocess executed')
        cs_print.ok('DONE!')

            