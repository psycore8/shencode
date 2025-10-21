########################################################
### ShenCode Module
###
### Name: XOR-Poly Encoder
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.helper import CheckFile
from utils.const import tpl_path
from utils.binary import replace_bytes_at_offset
from os import path as osp
from modules.xor import module as xormod

CATEGORY    = 'encoder'
DESCRIPTION = 'Polymorphic XOR encoder'

cs = ConsoleStyles()

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR stub')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR stub')

    grpout = parser.add_argument_group('output')
    grpout.add_argument('-o', '--output', help= 'Output file or buffer for XORPOLY encoding')

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'X0RP0LY-ENC'
    shellcode = b''
    xored_shellcode = b''
    data_size = 0
    hash = ''
    relay_input     = False
    relay_output    = False

    def __init__(self, input, output, key):
       self.input_file = input
       self.output_file = output
       self.template_file = f'{tpl_path}xor-stub.tpl'
       self.xor_key = key

    def LoadHeader(self):
        with open(self.template_file, "rb") as file:
            self.shellcode = file.read()

    def LoadPayload(self):
       with open(self.input_file, 'rb') as file:
          self.shellcode = file.read()

    def AppendShellcode(self):
        self.shellcode += self.xored_shellcode

    def WriteToFile(self):
      outputfile = self.output_file #xor.Output_File
      with open(outputfile, 'wb') as file:
        file.write(self.shellcode)

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        xor_enc = xormod('', '', 0, False, 'encode')
        self.xored_shellcode = xor_enc.xor_crypt_bytes(self.shellcode, self.xor_key)
        cs.console_print.note(f'Try to load stub from {self.template_file}')
        if CheckFile(self.template_file):
          self.LoadHeader()
          cs.action_open_file2(self.template_file)
        else:
            cs.console_print.error(f'File {self.template_file} not found or cannot be opened.')
            return
        if self.relay_input:
            self.shellcode = self.input_file
        else:
            cs.console_print.note('Try to append shellcode...')
            if CheckFile(self.input_file):
                self.LoadPayload()
                cs.action_open_file2(self.input_file)
            else:
                cs.console_print.error(f'File {self.input_file} not found or cannot be opened.')
                return
        self.AppendShellcode()
        cs.console_print.note(f'Changing key to {self.xor_key} (0x{self.xor_key:08X})')
        self.shellcode = replace_bytes_at_offset(self.shellcode, 5, self.xor_key)
        if not self.relay_output:
            cs.console_print.note('Try to write XORPOLY shellcode to file')
            self.WriteToFile()
            cs.action_save_file2(self.output_file)
        else:
           cs.console_print.ok('DONE!')
           return self.shellcode
        cs.console_print.ok('DONE!')

    
        