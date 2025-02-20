import base64
from itertools import cycle
from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR encoding')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR encoding')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR encoding')

    grp = parser.add_argument_group('additional')
    grp.add_argument('-v', '--verbose', action='store_true', help='Show encrypted bytes')

class xor_encoder:
    Author = 'psycore8'
    Description = 'XOR encoder for payloads'
    Version = '2.1.0'
    DisplayName = 'XOR-ENCODER'
    hash = ''
    data_size = 0
    shellcode = bytes
    mod_shellcode = bytes
    out = list

    def __init__(self, input_file, output_file, xor_key, verbose):
        self.input_file = input_file
        self.output_file = output_file
        self.xor_key = xor_key
        self.verbose = verbose

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.output_try': f'{nstate.s_note} Try to write XORed shellcode to file',
            'proc.try'       : f'{nstate.s_note} Try to generate generate XORed shellcode',
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
        #print(out)
        return bytes(self.out)
    
    def open_file(self):
        try:
            with open(self.input_file, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False
        
    def write_to_file(self):
        with open(self.output_file, 'wb') as file:
            file.write(self.mod_shellcode)
    
    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        if CheckFile(self.input_file):
            self.open_file()
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
            self.msg('proc.try')
            self.mod_shellcode = self.xor_crypt_bytes(self.shellcode, self.xor_key)
            if self.verbose:
                self.msg('proc.verbose')
            self.msg('proc.output_try')
            self.write_to_file()
            if CheckFile(self.output_file):
                self.data_size, self.hash = GetFileInfo(self.output_file)
                self.msg('proc.output_ok')
            else:
                self.msg('error.output', True)
        else:
            self.msg('error.input', True)
        self.msg('post.done')



            
