########################################################
### Start Subprocess Module
### Status: migrated 085
###
########################################################

#from utils.helper import nstate
from utils.style import *
import subprocess

CATEGORY    = 'core'
DESCRIPTION = 'Execute a subprocess'

arglist = {
    'command_line':         { 'value': [], 'desc': 'Command line to execute' }
}

def register_arguments(parser):
    parser.add_argument('-c', '--command-line', default=[], help=arglist['command_line']['desc'])

class module:
    Author =      'psycore8'
    Version =     '0.1.1'
    DisplayName = 'SUBPR0CESS'
    hash = ''
    data_size = 0
    shell_path = '::core::subproc'

    def __init__(self, command_line):
        self.command_line = command_line

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.proc'     : f'{s_fail} Error during processing: {MsgVar} {self.command_line}',
            'post.done'      : f'{s_ok} DONE!',
            'proc.ok'        : f'{s_ok} Subprocess executed'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def run_subprocess(self):
        subprocess.run(self.command_line)

    def process(self):
        m = self.msg
        m('pre.head')

        result = subprocess.run(self.command_line).returncode
        
        if result != 0:
            m('error.proc', f'{result}', True)
        m('proc.ok')
        m('post.done')

            