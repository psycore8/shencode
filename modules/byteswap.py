########################################################
### AES Module
### Status: cleaned, 085
### 
########################################################

#from utils.helper import nstate as nstate
from utils.style import *
from utils.helper import CheckFile, GetFileInfo
from utils.const import tpl_path
from utils.binary import replace_bytes_at_offset
from os import path as osp

CATEGORY    = 'encoder'
DESCRIPTION = '(Deprecated) Polymorphic encoder stub'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file or buffer to use with byteswap stub')
    parser.add_argument('-o', '--output', help= 'outputfile for byteswap stub')
    parser.add_argument('-k', '--key', type=int, help='the XOR key to use')

class module:
    Author = 'psycore8'
    Version = '2.1.5'
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

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.size'     : f'{s_fail} Shellcode exceeds max size of 255 bytes',
            'error.input'    : f'{s_fail} File {self.input} not found or cannot be opened.',
            'error.output'   : f'{s_fail} File {self.output} not found or cannot be opened.',
            'error.template' : f'{s_fail} File {self.template_file} not found or cannot be opened.',
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input} loaded!\n{s_note} Size of shellcode {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.output_ok' : f'{s_ok} File {self.output} created!\n{s_note} Size {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.stub_ok'   : f'{s_ok} Stub {self.template_file} loaded!\n{s_note} Size {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.input_try' : f'{s_note} Try to open file {self.input}',
            'proc.output_try': f'{s_note} Try to write XORPOLY shellcode to file',
            'proc.stub'      : f'{s_note} Try to load stub from {self.template_file}',
            'proc.try'       : f'{s_note} Try to append shellcode',
            'proc.key'       : f'{s_note} Changing key to {self.xor_key} and patching length',
            'proc.stats'     : f'{s_note} Shellcode size: {len(self.Shellcode)} bytes'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

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
            self.msg('error.size', True)

    def AppendShellcode(self):
        self.Modified_Shellcode += self.encrypt(self.Shellcode, int(self.xor_key))
        size = len(self.Modified_Shellcode)
        print(f'{OKBLUE} XORed payload added, size of shellcode {size} bytes')

    def WriteToFile(self):
      with open(self.output, 'wb') as file:
        file.write(self.Modified_Shellcode)

    def process(self):
       self.msg('pre.head')
       Length_Offset = 10
       XOR_Key_Offset = 36
       self.msg('proc.stub')
       if CheckFile(self.template_file):
           self.data_size, self.hash = GetFileInfo(self.template_file)
           self.msg('proc.stub_ok')
           self.LoadHeader()
           self.msg('proc.stats')
       else:
            self.msg('error.template', True)
       self.msg('proc.input_try')
       if CheckFile(self.input):
        self.data_size, self.hash = GetFileInfo(self.input)
        self.msg('proc.input_ok')   
        self.LoadShellcode()
       else:
           self.msg('error.input', True)
       self.msg('proc.try')
       self.AppendShellcode()
       self.msg('proc.stats')
       self.msg('proc.key')
       self.Modified_Shellcode = replace_bytes_at_offset(self.Modified_Shellcode, Length_Offset, self.Shellcode_Length)
       self.Modified_Shellcode = replace_bytes_at_offset(self.Modified_Shellcode, XOR_Key_Offset, self.xor_key)
       if not self.relay:
        self.WriteToFile()
        if CheckFile(self.output):
            self.data_size, self.hash = GetFileInfo(self.output)
            self.msg('proc.output_ok') 
        else:
            self.msg('error.output', True)
       elif self.relay:
        self.msg('post.done')
        return self.Modified_Shellcode    
       self.msg('post.done')