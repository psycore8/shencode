########################################################
### ShenCode Module
###
### Name: Extract Module
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.helper import GetFileInfo
import struct

CATEGORY    = 'core'
DESCRIPTION = 'Extract bytes or sections from PE files'

cs = ConsoleStyles()

arglist = {
    'input':                { 'value': None, 'desc': 'Input file for extract module'},
    'output':               { 'value': None, 'desc': 'Output file with extracted bytes'},
    'extract_range':        { 'value': [0,0], 'desc': 'Defines the range to extract, takes 2 arguments: -e 100 150'},
    'extract_section':      { 'value': None, 'desc': 'Extract a section from exe, dll, obj'}
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])
    parser.add_argument('-o', '--output', help=arglist['output']['desc'])

    exd = parser.add_argument_group('Extract data')
    exd.add_argument('-e', '--extract-range', nargs=2, default=[0, 0], help=arglist['extract_range']['desc'])
    exd.add_argument('-s', '--extract-section', help=arglist['extract_section']['desc'])

class module:
    Author =      'psycore8'
    Version =     '0.9.0'
    DisplayName = 'BYTE-XTRACT0R'
    hash = ''
    data_size = 0
    shell_path = '::core::extract'

    def __init__(self, input, output, extract_range=[0, 0], extract_section=None):
        self.input = input
        self.output = output
        self.extract_range = extract_range
        self.extract_section = extract_section

    def extract_section_from_file(self, file_name, section_name, optional_header=False):
        with open(file_name, "rb") as f:
            data = f.read()

        # number of sections after DOS Header
        num_sections = struct.unpack_from("<H", data, 2)[0]

        # section table at offset 14h without optional header, section table has a length of 40 bytes
        section_offset = 0x14
        if optional_header:
            section_offset = section_offset + 20
        section_size = 40 

        for i in range(num_sections):
            section_data = data[section_offset + i * section_size : section_offset + (i + 1) * section_size]
            name = section_data[:8].strip(b"\x00").decode()
            if name == section_name:
                raw_data_offset = struct.unpack_from("<I", section_data, 20)[0]
                raw_data_size = struct.unpack_from("<I", section_data, 16)[0]
                section_buffer = data[raw_data_offset : raw_data_offset + raw_data_size]
                return section_buffer

        cs.print(f'{section_name} section not found!', cs.state_fail)
        return None

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        cs.print('Try to open file', cs.state_note)
        try:
            with open(self.input, "rb") as file:
                shellcode = file.read()
                self.data_size, self.hash = GetFileInfo(self.input)
                cs.action_open_file2(self.input)
        except FileNotFoundError:
            self.msg('error.input', True)
        if self.extract_section == None:
            if isinstance(self.extract_range, str): pass
            bytes_from = int(self.extract_range[0])
            bytes_until = int(self.extract_range[1])
            if bytes_from > -1 and bytes_until > 0:
                cs.print(f'Try to extract bytes from {self.extract_range[0]} to {self.extract_range[1]}', cs.state_note)
                shellcode_new = shellcode[bytes_from:bytes_until]
        else:
            shellcode_new = self.extract_section_from_file(self.input, self.extract_section)
        cs.print('Writing to file...', cs.state_note)
        with open(self.output, 'wb') as file:
            file.write(shellcode_new)
        cs.action_save_file2(self.output)
        cs.print('DONE!', cs.state_ok)