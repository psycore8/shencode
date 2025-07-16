########################################################
### AES Module
### Status: migrated 085
### 
########################################################

#from utils.helper import nstate as nstate
from utils.style import *
from utils.helper import CheckFile, GetFileInfo
from utils.const import tpl_path
from utils.binary import replace_bytes_at_offset
from os import path as osp
from modules.xor import module as xormod

CATEGORY    = 'encoder'
DESCRIPTION = 'Polymorphic XOR encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR stub')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR stub')

    grpout = parser.add_argument_group('output')
    grpout.add_argument('-o', '--output', help= 'Output file or buffer for XORPOLY encoding')

class module:
    Author = 'psycore8'
    Version = '2.1.5'
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

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{s_fail} File {self.output_file} not found or cannot be opened.',
            'error.template' : f'{s_fail} File {self.template_file} not found or cannot be opened.',
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input_file} loaded!\n{s_note} Size of shellcode {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.output_ok' : f'{s_ok} File {self.output_file} created!\n{s_note} Size {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.stub_ok'   : f'{s_ok} Stub {self.template_file} loaded!\n{s_note} Size {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.input_try' : f'{s_note} Try to open file {self.input_file}',
            'proc.output_try': f'{s_note} Try to write XORPOLY shellcode to file',
            'proc.stub'      : f'{s_note} Try to load stub from {self.template_file}',
            'proc.try'       : f'{s_note} Try to append shellcode',
            'proc.key'       : f'{s_note} Changing key to {self.xor_key}',
            'proc.stats'     : f'{s_note} Shellcode size: {len(self.shellcode)} bytes'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

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
        self.msg('pre.head')
        xor_enc = xormod('', '', 0, False, 'encode')
        self.xored_shellcode = xor_enc.xor_crypt_bytes(self.shellcode, self.xor_key)
        self.msg('proc.stub')
        if CheckFile(self.template_file):
          self.data_size, self.hash = GetFileInfo(self.template_file)
          self.LoadHeader()
          self.msg('proc.stub_ok')
          self.msg('proc.stats')
        else:
            self.msg('error.template', True)
        if self.relay_input:
            self.shellcode = self.input_file
        else:
            self.msg('proc.try')
            if CheckFile(self.input_file):
                self.LoadPayload()
                self.data_size, self.hash = GetFileInfo(self.input_file)
                self.msg('proc.input_ok')
            else:
                self.msg('error.input', True)
        self.AppendShellcode()
        self.msg('proc.stats')
        self.msg('proc.key')
        self.shellcode = replace_bytes_at_offset(self.shellcode, 5, self.xor_key)
        if not self.relay_output:
            self.msg('proc.output_try')
            self.WriteToFile()
            if CheckFile(self.output_file):
                self.data_size, self.hash = GetFileInfo(self.output_file)
                self.msg('proc.output_ok')
            else:
                self.msg('error.output', True)
        else:
           self.msg('post.done')
           print('\n')
           return self.shellcode
        self.msg('post.done')

    
        