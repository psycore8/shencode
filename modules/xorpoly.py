########################################################
### AES Module
### Status: migrated to 082
### 
########################################################

from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from utils.const import tpl_path
from utils.binary import replace_bytes_at_offset
from os import path as osp
from modules.xor import module as xormod

CATEGORY    = 'encoder'
DESCRIPTION = 'Polymorphic XOR encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR stub')
    #parser.add_argument('-o', '--output', help= 'Outputfile for XOR stub')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR stub')

    grpout = parser.add_argument_group('output')
    grpout.add_argument('-o', '--output', help= 'Output file or buffer for XORPOLY encoding')
    #grpout.add_argument('-r', '--relay', choices=relay.relay_options, help='Relay to module')

class module:
    Author = 'psycore8'
    #Description = 'create payload from a raw file, encode with xor, add to xor stub'
    Version = '2.1.3'
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
       #self.relay_command = relay_command
    #    with open(self.input_file, 'rb') as file:
    #       self.shellcode = file.read()
    #    if relay_command != None:
    #       self.relay = True

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'error.template' : f'{nstate.s_fail} File {self.template_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded!\n{nstate.s_note} Size of shellcode {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created!\n{nstate.s_note} Size {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.stub_ok'   : f'{nstate.s_ok} Stub {self.template_file} loaded!\n{nstate.s_note} Size {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.output_try': f'{nstate.s_note} Try to write XORPOLY shellcode to file',
            'proc.stub'      : f'{nstate.s_note} Try to load stub from {self.template_file}',
            'proc.try'       : f'{nstate.s_note} Try to append shellcode',
            'proc.key'       : f'{nstate.s_note} Changing key to {self.xor_key}',
            'proc.stats'     : f'{nstate.s_note} Shellcode size: {len(self.shellcode)} bytes'
            #'proc.verbose'   : f'\n{self.out}\n'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    # def LoadInputFile(self):
    #    with open(self.input_file, 'rb') as file:
    #       self.shellcode = file.read()

    def LoadHeader(self):
        with open(self.template_file, "rb") as file:
            self.shellcode = file.read()

    def LoadPayload(self):
       with open(self.input_file, 'rb') as file:
          self.shellcode = file.read()

    def AppendShellcode(self):
        self.shellcode += self.xored_shellcode

    # def replace_bytes_at_offset(data, offset, new_bytes):
    #     data = bytearray(data)
    #     data[offset] = new_bytes
    #     data.append(int(new_bytes))
    #     return bytes(data)

    def WriteToFile(self):
      outputfile = self.output_file #xor.Output_File
      with open(outputfile, 'wb') as file:
        file.write(self.shellcode)

    def process(self):
        #Offset = 5
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
           #relay.start_relay(self.relay_command, self.shellcode)
           return self.shellcode
        self.msg('post.done')

    
        