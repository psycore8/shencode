import base64
from itertools import cycle
from utils.style import *
from utils.helper import CheckFile
from tqdm import tqdm

CATEGORY    = 'encoder'
DESCRIPTION = 'XOR encoder for payloads'

cs = ConsoleStyles()

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR encoding')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR encoding')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR encoding')

    grp = parser.add_argument_group('additional')
    grp.add_argument('-m', '--mode', choices=['encode', 'decode'], default='encode', help='Set the operation mode')
    grp.add_argument('-v', '--verbose', action='store_true', help='Show encrypted bytes')

class module:
    Author = 'psycore8'
    Version = '0.9.0'
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
        cs.module_header(self.DisplayName, self.Version)
        cs.print('Try to open file', cs.state_note)
        if CheckFile(self.input):
            self.open_file()

            cs.action_open_file2(self.input)
            cs.print('Try to generate XORed shellcode', cs.state_note)
            if self.mode == 'encode':
                for i in tqdm (range (100), colour='magenta', leave=False):
                    self.mod_shellcode = self.xor_crypt_bytes(self.shellcode, self.xor_key)
            elif self.mode == 'decode':
                for i in tqdm (range (100), colour='magenta', leave=False):
                    self.mod_shellcode = self.xor_decrypt_bytes(self.shellcode, self.xor_key)
            if self.verbose:
                cs.print(f'\n{self.out}\n', cs.state_note)
            if not self.relay:
                CheckFile(self.output)
                self.write_to_file()
                cs.print('Try to write XORed shellcode to file', cs.state_note)
                cs.action_save_file2(self.output)
            elif self.relay:
                cs.print('DONE!', cs.state_ok)
                cs.print('\n')
                return self.mod_shellcode
                exit()
        else:
            cs.print(f'File {self.input} not found or cannot be opened!', cs.state_fail)
            return
        cs.print('DONE!', cs.state_ok)



            
