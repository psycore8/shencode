########################################################
### Download Module
### Status: dev
###
########################################################

import requests
from utils.helper import nstate, GetFileInfo

CATEGORY    = 'dev'
DESCRIPTION = 'Download files'

def register_arguments(parser):
    parser.add_argument('-o', '--output', required=True, help= 'Output file')
    parser.add_argument('-p', '--protocol', choices=['http'], required=True, help='Download protocol')
    parser.add_argument('-u', '--uri', required=True, help='URI to file')

class module:
    Author = 'psycore8'
    Version = '0.0.1'
    DisplayName = 'D0WNL04D3R'
    data_size = int
    hash = ''
    data_bytes = bytes
    #relay_input = False
    relay_output = False

    def __init__(self, output, protocol, uri):
        self.output = output
        self.protocol = protocol
        self.uri = uri

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.out'       : f'{nstate.s_ok} File created in {self.output}\n{nstate.s_info} Hash: {self.hash}',
            'mok'            : f'{nstate.s_ok} {MsgVar}',
            'mnote'          : f'{nstate.s_note} {MsgVar}',
            'merror'         : f'{nstate.s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def process(self):
        m = self.msg
        m('pre.head')
        if hasattr(self, self.protocol):
            processed_data = getattr(self, self.protocol)()
            if not processed_data:
                m('merror', 'Error during download', True)
            if self.relay_output:
                return processed_data
            m('mnote', 'Trying to write output file...')
            if self.save_file(processed_data):
                self.data_size, self.hash = GetFileInfo(self.output)
                m('proc.out')
            else:
                m('merror', f'Error saving {self.output}', True)
        else:
            m('merror', f'Protocol {self.protocol} is not valid!', True)
        m('post.done')

    def http(self):
        r = requests.get(self.uri)
        if r.status_code == 200:
            return r._content
        else:
            return False
        
    def save_file(self, data):
        try:
            with open(self.output, 'wb') as f:
                f.write(data)
            return True
        except:
            return False