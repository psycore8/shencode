########################################################
### XOR Module
### Status: migrated to 081
########################################################

import base64
from itertools import cycle
import utils.relay as relay
from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo
from tqdm import tqdm

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR encoding')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR encoding')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR encoding')

    #grpout = parser.add_argument_group('output')
    #grpout.add_argument('-o', '--output', help= 'Output file or buffer for XOR encoding')
    #grpout.add_argument('-r', '--relay', choices=relay.relay_options, help='Relay to module')

    grp = parser.add_argument_group('additional')
    #grp.add_argument('-ch', '--chain', choices=['inject', 'ntinject'], required=False, help='If set, the output will be redirected to the choosen module')
    grp.add_argument('-m', '--mode', choices=['encode', 'decode'], default='encode', help='Set the operation mode')
    grp.add_argument('-v', '--verbose', action='store_true', help='Show encrypted bytes')

class module:
    Author = 'psycore8'
    Description = 'XOR encoder for payloads'
    Version = '2.1.2'
    DisplayName = 'XOR-ENCODER'
    hash = ''
    data_size = 0
    shellcode = bytes
    mod_shellcode = bytes
    out = list
    relay = False

    def __init__(self, input, output, key, verbose, mode):
        self.input = input
        self.output = output
        self.xor_key = key
        self.verbose = verbose
        self.mode = mode
        # self.relay_command = relay_command
        # if relay_command != None:
        #     self.relay = True

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input}',
            'proc.output_try': f'{nstate.s_note} Try to write XORed shellcode to file',
            'proc.try'       : f'{nstate.s_note} Try to generate XORed shellcode',
            'proc.verbose'   : f'\n{self.out}\n'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def xor_crypt_string(data, key, encode = False, decode = False):
        if decode:
            data_bytes = base64.b64decode(data)
            data = data_bytes.decode("utf-8")
        xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
   
        if encode:
            data_bytes = base64.b64encode(xored.encode("utf-8"))
            return data_bytes.decode("utf-8")
        return xored
   
    def xor_crypt_bytes(self, data, key):
        self.out = [x ^ key for x in data]
        return bytes(self.out)
    
    def xor_decrypt_bytes(self, data, key):
        self.out = [x ^ key for x in data]
        return bytes(self.out)
    
    def open_file(self):
        try:
            with open(self.input, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False
        
    def write_to_file(self):
        with open(self.output, 'wb') as file:
            file.write(self.mod_shellcode)
    
    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        if CheckFile(self.input):
            self.open_file()
            self.data_size, self.hash = GetFileInfo(self.input)
            self.msg('proc.input_ok')
            self.msg('proc.try')
            if self.mode == 'encode':
                for i in tqdm (range (100), colour='magenta', leave=False):
                    self.mod_shellcode = self.xor_crypt_bytes(self.shellcode, self.xor_key)
            elif self.mode == 'decode':
                for i in tqdm (range (100), colour='magenta', leave=False):
                    self.mod_shellcode = self.xor_decrypt_bytes(self.shellcode, self.xor_key)
            if self.verbose:
                self.msg('proc.verbose')
            if not self.relay:
                CheckFile(self.output)
                self.msg('proc.output_try')
                self.write_to_file()
                self.data_size, self.hash = GetFileInfo(self.output)
                self.msg('proc.output_ok')
            elif self.relay:
                self.msg('post.done')
                print('\n')
                return self.mod_shellcode
                exit()
            else:
                self.msg('error.output', True)
        else:
            self.msg('error.input', True)
        self.msg('post.done')



            
