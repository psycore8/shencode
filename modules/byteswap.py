########################################################
### ShenCode Module
###
### Name: ByteSwap Encoder
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.helper import CheckFile
from utils.const import tpl_path
from utils.binary import replace_bytes_at_offset
from os import path as osp

CATEGORY    = 'encoder'
DESCRIPTION = '(Deprecated) Polymorphic encoder stub'

cs = ConsoleStyles()

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file or buffer to use with byteswap stub')
    parser.add_argument('-o', '--output', help= 'outputfile for byteswap stub')
    parser.add_argument('-k', '--key', type=int, help='the XOR key to use')

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'BYTESWAP-ENC'
    Shellcode = ''
    Shellcode_Length = 0
    Modified_Shellcode = bytes
    data_size = 0
    hash = ''
    relay = False

    def __init__(self, input, output, key):
        self.input = input
        self.output = output
        self.template_file = f'{tpl_path}byteswap-short.tpl'
        self.xor_key = key

    def encrypt(self, data: bytes, xor_key: int) -> bytes:
        transformed = bytearray()
        prev_enc_byte = 0
        for i, byte in enumerate(data):
            if i % 2 == 0: # even byte positions
                enc_byte = byte ^ xor_key
            else:          # odd byte positions
                enc_byte = byte ^ prev_enc_byte
            
            transformed.append(enc_byte)
            prev_enc_byte = enc_byte

        return bytes(transformed)

    def LoadHeader(self):
            with open(self.template_file, "rb") as file:
                self.Modified_Shellcode = file.read()

    def LoadShellcode(self):
        with open(self.input, 'rb') as file:
            self.Shellcode = file.read()
        self.Shellcode_Length = len(self.Shellcode)
        if self.Shellcode_Length > 255:
            cs.console_print.error('Shellcode exceeds max size of 255 bytes')

    def AppendShellcode(self):
        self.Modified_Shellcode += self.encrypt(self.Shellcode, int(self.xor_key))
        size = len(self.Modified_Shellcode)
        cs.console_print.ok(f'XORed payload added, size of shellcode {size} bytes')

    def WriteToFile(self):
      with open(self.output, 'wb') as file:
        file.write(self.Modified_Shellcode)

    def process(self):
       cs.module_header(self.DisplayName, self.Version)
       Length_Offset = 10
       XOR_Key_Offset = 36
       cs.console_print.note(f'Try to load stub from {self.template_file}')
       if CheckFile(self.template_file):
           cs.action_open_file2(self.template_file)
           self.LoadHeader()
           cs.console_print.note(f'Shellcode size: {len(self.Shellcode)} bytes')
       else:
            cs.console_print.error(f'File {self.template_file} not found or cannot be opened.')
            return
       if CheckFile(self.input):
        cs.action_open_file2(self.input)
        self.LoadShellcode()
       else:
           cs.console_print.error(f'File {self.input} not found or cannot be opened.')
       cs.console_print.note('Try to append shellcode')
       self.AppendShellcode()
       cs.console_print.note(f'Shellcode size: {len(self.Shellcode)} bytes')
       cs.console_print.note(f'Changing key to {self.xor_key} and patching length')
       self.Modified_Shellcode = replace_bytes_at_offset(self.Modified_Shellcode, Length_Offset, self.Shellcode_Length)
       self.Modified_Shellcode = replace_bytes_at_offset(self.Modified_Shellcode, XOR_Key_Offset, self.xor_key)
       if not self.relay:
        self.WriteToFile()
        cs.action_save_file2(self.output)
       elif self.relay:
        cs.console_print.ok('DONE!')
        return self.Modified_Shellcode    
       cs.console_print.ok('DONE!')
