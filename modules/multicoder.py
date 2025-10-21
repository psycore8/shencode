########################################################
### ShenCode Module
###
### Name: Multicoder Module
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import base64
import os
import pickle

from utils.style import *
from utils.helper import GetFileInfo
from utils.const import priv_key, pub_key

CATEGORY    = 'encoder'
DESCRIPTION = 'En- / Decoder for different algorithms. Supports: AES, Base32, Base64, RSA'

cs = ConsoleStyles()

arglist = {
    'algorithm':     { 'value': None, 'desc': 'Choose an algorithm: base32, base64, aes, rsa' },
    'mode':          { 'value': None, 'desc': 'Operation mode, choose encode / decode' },
    'input':         { 'value': None, 'desc': 'Input file to process' },
    'key':           { 'value': None, 'desc': 'If required, set the en- / decryption key' },
    'output':        { 'value': None, 'desc': 'Output file' }
}

def register_arguments(parser):
    parser.add_argument('-a', '--algorithm' ,choices=['base32', 'base64', 'aes', 'rsa'], required=True, help=arglist['algorithm']['desc'])
    parser.add_argument('-m', '--mode', choices=['encode', 'decode'], required=True, help=arglist['mode']['desc'])
    parser.add_argument('-i', '--input', required=True, help=arglist['input']['desc'])
    parser.add_argument('-k', '--key', required=False, default=None, help=arglist['key']['desc'])
    parser.add_argument('-o', '--output', required=True, help=arglist['output']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'MultiC0DER'
    data_size = int
    hash = ''
    data_bytes = bytes
    relay_input = False
    relay_output = False
    shell_path = '::encoder::multicoder'

    def __init__(self, algorithm, mode, input, key, output):
        self.algorithm = algorithm
        self.mode = mode
        self.input = input
        self.key = key
        self.output = output

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        cs.console_print.note('Load input file...')
        if self.load_file():
            if not self.relay_input:
                self.data_size, self.hash = GetFileInfo(self.input)
                cs.action_open_file2(self.input)
        else:
            cs.console_print.error(f'Error loading file {self.input}')
            return
        cs.console_print.note(f'Process input with {self.algorithm.upper()}')
        if hasattr(self, self.algorithm):
            processed_data = getattr(self, self.algorithm)()
        else:
            cs.console_print.error(f'Algorithm {self.algorithm} is not valid')
            return
        if processed_data == None:
            cs.console_print.error('Error while processing data')
            return
        if self.relay_output:
            return processed_data
        else:
            self.save_file(processed_data)
            cs.action_save_file2(self.output)
        cs.console_print.ok('DONE!')


    def load_file(self):
        try:
            with open(self.input, 'rb') as f:
                self.data_bytes = f.read()
            return True
        except:
            return False
            
    def save_file(self, data):
        try:
            with open(self.output, 'wb') as f:
                f.write(data)
            return True
        except:
            return False
            
    def base64(self):
        if self.mode == 'encode':
            processed_data = base64.b64encode(self.data_bytes)
        elif self.mode == 'decode':
            processed_data = base64.b64decode(self.data_bytes)
        else:
            processed_data = None
        return processed_data
    
    def base32(self):
        if self.mode == 'encode':
            processed_data = base64.b32encode(self.data_bytes)
        elif self.mode == 'decode':
            processed_data = base64.b32decode(self.data_bytes)
        else:
            processed_data = None
        return processed_data

    def rsa(self):
        if not os.path.exists(priv_key) or not os.path.exists(pub_key):
            cs.console_print.note('Private and/or public key not found, set generate flag!')
            gen_keys = True
        else:
            gen_keys = False

        from utils.crypt import rsa_worker
        rw = rsa_worker()
        if gen_keys:
            rw.generate_key_pair()
            rw.save_key_pair(priv_key, pub_key)

        if self.mode == 'encode':
            fn_root, fn_extension = os.path.splitext(self.output)
            key_file = f'{fn_root}.key'
            rw.load_public_key(pub_key)
            processed_data = self.aes()
            rw.rsa_encrypt(self.key.encode('utf-8'))
            rw.save_encrypted_key(key_file)
            return processed_data
        elif self.mode == 'decode':
            fn_root, fn_extension = os.path.splitext(self.input)
            key_file = f'{fn_root}.key'
            rw.load_private_key(priv_key)
            rw.load_encrypted_key(key_file)
            self.key = rw.rsa_decrypt()
            processed_data = self.aes()
            return processed_data
        else:
            cs.console_print.error('Mode not valid, try encode/decode')
            return
    
    def aes(self):
        from utils.crypt import aes_worker
        aw = aes_worker()
        if self.mode == 'encode':
            buffer, salt, iv = aw.aes_encrypt(self.data_bytes, self.key.encode('utf-8'))
            processed_data = pickle.dumps((buffer, salt, iv))
        elif self.mode == 'decode':
            buffer, salt, iv = pickle.loads(self.data_bytes)
            processed_data = aw.aes_decrypt(buffer, self.key.encode('utf-8'), salt, iv)
        else:
            processed_data = None
        return processed_data
