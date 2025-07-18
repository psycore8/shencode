########################################################
### UUID Module
### Status: migrated 084
### 
########################################################

from utils.helper import nstate as nstate
from utils.helper import GetFileInfo

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as UUID strings'

arglist = {
    'input':       { 'value': None, 'desc': 'Input file for UUID encoding' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])

class module:
    Author = 'psycore8'
    Version = '2.2.4'
    DisplayName = 'UUID-OBF'
    UUID_string = ''
    hash = ''
    data_size = 0
    shellcode = b''
    obf_String = ''
    var_counter = 0
    shell_path = '::obfuscate::uuid'


    def __init__(self, input):
        self.input_file = input

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'post.out'       : f'{self.UUID_string}',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{nstate.s_note} Try generate UUIDs'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def string_to_uuid(self, string_value):
        formatted_string = f"{string_value[:8]}-{string_value[8:12]}-{string_value[12:16]}-{string_value[16:20]}-{string_value[20:]}"
        return formatted_string
    
    def open_file(self, filename):
        try:
            with open(filename, 'rb') as f:
                self.shellcode = f.read()
            return True
        except FileNotFoundError:
            return False

    def split_string_into_blocks(self, s, block_size=16):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return [s[i:i + block_size] for i in range(0, len(s), block_size)]
    
    def CreateVar(self):
        self.obf_String = ''
        blocks = self.split_string_into_blocks(self.shellcode, 32)
        self.obf_string = f'std::vector<std::string> sID = '
        self.obf_string += '{\n'
        for block in blocks:
            s = self.string_to_uuid(block.hex())
            self.obf_string += f'\"{s}\",\n'
        self.obf_string = self.obf_string[:-2] + ' };'
        return self.obf_string
    
    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        if self.open_file(self.input_file):
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
        else:
            self.msg('error.input', True)
        self.msg('proc.try')
        self.UUID_string = self.CreateVar()
        self.msg('post.out')
        self.msg('post.done')