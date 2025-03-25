########################################################
### AES Module
### Status: migrated to 081
########################################################

from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo
from os import path as os_path
import struct

CATEGORY = 'core'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for example module')
    parser.add_argument('-o', '--output', help='Output file with extracted bytes')

    exd = parser.add_argument_group('Extract data')
    exd.add_argument('-e', '--extract-range', nargs=2, default=[0, 0], type=int, help='Defines the range to extract, takes 2 arguments: -e 100 150')
    exd.add_argument('-s', '--extract-section', help='Extract a section from exe, dll, obj')

    dpc = parser.add_argument_group('Deprecated, will be removed in a future release')
    dpc.add_argument('-so', '--start-offset', help='begin extraction from this offset', deprecated=True)
    dpc.add_argument('-eo', '--end-offset', help='extract until here', deprecated=True)


class module:
    Author =      'psycore8'
    Description = 'extract shellcode from/to offset'
    Version =     '2.1.3'
    DisplayName = 'BYTE-XTRACT0R'
    hash = ''
    data_size = 0

    def __init__(self, input, output, extract_range, start_offset, end_offset, extract_section=None):
        self.input = input
        self.output = output
        self.extract_range = extract_range
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.extract_section = extract_section

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input}',
            'proc.output_try': f'{nstate.s_note} Writing to file...',
            'proc.try'       : f'{nstate.s_note} Try to extract bytes from 0x{self.start_offset} to 0x{self.end_offset}',
            'proc.try2'       : f'{nstate.s_note} Try to extract bytes from {self.extract_range[0]} to {self.extract_range[1]}',
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

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

        print(".text section not found!")
        return None

    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        #short_fn = os_path.basename(self.input)
        try:
            with open(self.input, "rb") as file:
                shellcode = file.read()
                self.data_size, self.hash = GetFileInfo(self.input)
                self.msg('proc.input_ok')
        except FileNotFoundError:
            self.msg('error.input', True)
        if self.extract_section == None:
            if self.start_offset != None and self.end_offset != None:
                self.msg('proc.try')
                shellcode_new = shellcode[int(self.start_offset):int(self.end_offset)]
            elif self.extract_range[0] > -1 and self.extract_range[1] > 0:
                self.msg('proc.try2')
                shellcode_new = shellcode[int(self.extract_range[0]):int(self.extract_range[1])]
        else:
            shellcode_new = self.extract_section_from_file(self.input, self.extract_section)
        self.msg('proc.output_try')
        with open(self.output, 'wb') as file:
            file.write(shellcode_new)
        if CheckFile(self.output):
            self.data_size, self.hash = GetFileInfo(self.output)
            self.msg('proc.output_ok')
        else:
            self.msg('error.output', True)
        self.msg('post.done')