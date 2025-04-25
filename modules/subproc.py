########################################################
### Start Subprocess Module
### Status: migrated to 082
###
########################################################

from utils.helper import nstate
import subprocess

CATEGORY    = 'core'
DESCRIPTION = 'Execute a subprocess'

def register_arguments(parser):
    parser.add_argument('-c', '--command-line', default=[], help='Command line to execute')

class module:
    Author =      'psycore8'
    #Description = 'Helper module to execute a subprocess'
    Version =     '0.0.2'
    DisplayName = 'SUBPR0CESS'
    hash = ''
    data_size = 0

    def __init__(self, command_line):
        self.command_line = command_line

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.proc'     : f'{nstate.s_fail} Error during processing: {MsgVar} {self.command_line}',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.ok'        : f'{nstate.s_ok} Subprocess executed'
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

            