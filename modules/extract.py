from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo
from os import path as os_path

CATEGORY = 'core'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for example module')
    parser.add_argument('-o', '--output', help='Output file with extracted bytes')
    parser.add_argument('-so', '--start-offset', help='begin extraction from this offset')
    parser.add_argument('-eo', '--end-offset', help='extract until here')


class extract_shellcode:
    Author =      'psycore8'
    Description = 'extract shellcode from/to offset'
    Version =     '2.1.0'
    DisplayName = 'BYTE-XTRACT0R'
    hash = ''
    data_size = 0

    def __init__(self, input_file, output_file, start_offset, end_offset):
        self.input_file = input_file
        self.output_file = output_file
        self.start_offset = start_offset
        self.end_offset = end_offset

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.output_try': f'{nstate.s_note} Writing to file...',
            'proc.try'       : f'{nstate.s_note} Try to extract bytes from 0x{self.start_offset} to 0x{self.end_offset}',
            #'proc.verbose'   : f'\n{self.out}\n'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        short_fn = os_path.basename(self.input_file)
        try:
            with open(self.input_file, "rb") as file:
                shellcode = file.read()
                self.data_size, self.hash = GetFileInfo(self.input_file)
                self.msg('proc.input_ok')
        except FileNotFoundError:
            self.msg('error.input', True)
        self.msg('proc.try')
        shellcode_new = shellcode[int(self.start_offset):int(self.end_offset)]
        self.msg('proc.output_try')
        with open(self.output_file, 'wb') as file:
            file.write(shellcode_new)
        if CheckFile(self.output_file):
            self.data_size, self.hash = GetFileInfo(self.output_file)
            self.msg('proc.output_ok')
        else:
            self.msg('error.output', True)
        self.msg('post.done')