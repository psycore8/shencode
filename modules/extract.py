from utils.helper import nstate as nstate
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
    Version =     '2.0.0'

    def __init__(self, input_file, output_file, start_offset, end_offset):
        self.input_file = input_file
        self.output_file = output_file
        self.start_offset = start_offset
        self.end_offset = end_offset

    def process(self):
        print(f"{nstate.OKBLUE} try to open file")
        short_fn = os_path.basename(self.input_file)
        try:
            with open(self.input_file, "rb") as file:
                shellcode = file.read()
                print(f"{nstate.OKGREEN} reading {short_fn} successful!")
        except FileNotFoundError:
            print(f"{nstate.FAIL} file not found, exit")
            exit()
        print(f"{nstate.OKBLUE} extracting shellcode from {self.start_offset} to {self.end_offset}")
        shellcode_new = shellcode[int(self.start_offset):int(self.end_offset)]
        with open(self.output_file, 'wb') as file:
            file.write(shellcode_new)
        path = self.output_file
        cf = os_path.isfile(path)
        short_fn = os_path.basename(self.output_file)
        if cf == True:
            print(f"{nstate.OKGREEN} written shellcode to {short_fn}")
        else:
            print(f"{nstate.FAIL} error while writing")
            exit()