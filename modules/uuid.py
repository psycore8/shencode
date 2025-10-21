########################################################
### ShenCode Module
###
### Name: UUID Obfuscation
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
#from utils.helper import GetFileInfo, CheckFile

from rich.console import Console
import re


CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as UUID strings'

cs = ConsoleStyles()

arglist = {
    'input':       { 'value': None, 'desc': 'Input file for UUID encoding' },
    'output':      { 'value': None, 'desc': 'Output file for UUID encoding' },
    'reverse':     { 'value': False, 'desc': 'Reverse encoding from UUID to raw binary' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])
    parser.add_argument('-o', '--output', help=arglist['output']['desc'])
    parser.add_argument('-r', '--reverse', action='store_true', help=arglist['reverse']['desc'])

class module:
    out = Console()
    
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'UUID-OBF'
    UUID_string = ''
    hash = ''
    data_size = 0
    shellcode = b''
    obf_String = ''
    var_counter = 0
    shell_path = '::obfuscate::uuid'


    def __init__(self, input, output, reverse):
        self.input_file = input
        self.output = output
        self.reverse = reverse

    def string_to_uuid(self, string_value):
        formatted_string = f"{string_value[:8]}-{string_value[8:12]}-{string_value[12:16]}-{string_value[16:20]}-{string_value[20:]}"
        return formatted_string
    
    def uuid_to_bytes(self, uuid_string):
        cut_off_chars = len(uuid_string) - 3
        bytes_only = re.sub('[\n,"-]', '', uuid_string[33:cut_off_chars])
        binary_data = bytes.fromhex(bytes_only)
        return binary_data
    
    def open_file(self, filename):
        try:
            if self.reverse:
                file_access_mode = 'r'
            else:
                file_access_mode = 'rb'
            with open(filename, file_access_mode) as f:
                self.shellcode = f.read()
            return True
        except FileNotFoundError:
            return False
        
    def save_file(self, data):
        try:
            if isinstance(data, str):
                file_access_mode = 'w'
            else:
                file_access_mode = 'wb'
            with open(self.output, file_access_mode) as f:
                written = f.write(data)
                return written
        except:
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
        cs.module_header(self.DisplayName, self.Version)
        cs.console_print.note('Try to open file')
        if self.open_file(self.input_file):
            cs.action_open_file2(self.input_file)
        else:
            cs.console_print.error(f'File {self.input_file} not found or cannot be opened.')
            return
        cs.console_print.note('Try to generate output')
        if self.reverse:
            data = self.uuid_to_bytes(self.shellcode)
            self.save_file(data)
            cs.action_save_file2(self.output)
        else:
            self.UUID_string = self.CreateVar()
            self.save_file(self.UUID_string)
            cs.action_save_file2(self.output)
        cs.console_print.ok('DONE!')
