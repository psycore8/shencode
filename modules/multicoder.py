########################################################
### MultiCODER Module
### Status: RC
### 
########################################################

import base64
import os
import pickle

from utils.helper import nstate
from utils.helper import GetFileInfo
from utils.const import priv_key, pub_key

CATEGORY    = 'encoder'
DESCRIPTION = 'En- / Decoder for different algorithms. Supports: AES, Base32, Base64, RSA'

def register_arguments(parser):
    parser.add_argument('-a', '--algorithm' ,choices=['base32', 'base64', 'aes', 'rsa'], required=True, help='')
    parser.add_argument('-m', '--mode', choices=['encode', 'decode'], required=True, help='Operation mode, choose encode / decode')
    parser.add_argument('-i', '--input', required=True, help='Input file')
    parser.add_argument('-k', '--key', required=False, default=None, help='If required, set the en- / decryption key')
    parser.add_argument('-o', '--output', required=True, help= 'Output file')

class module:
    Author = 'psycore8'
    Version = '0.1.0'
    DisplayName = 'MultiC0DER'
    data_size = int
    hash = ''
    data_bytes = bytes
    relay_input = False
    relay_output = False

    def __init__(self, algorithm, mode, input, key, output):
        self.algorithm = algorithm
        self.mode = mode
        self.input = input
        self.key = key
        self.output = output

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.mode'     : f'{nstate.s_fail} Please provide a valid mode: encode / decode',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_info} Size of encoded data: {self.data_size} bytes\n{nstate.s_info} Hash: {self.hash}',
            'proc.out'       : f'{nstate.s_ok} File created in {self.output}\n{nstate.s_info} Hash: {self.hash}',
            'mok'            : f'{nstate.s_ok} {MsgVar}',
            'mnote'          : f'{nstate.s_note} {MsgVar}',
            'merror'         : f'{nstate.s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def process(self):
        m = self.msg
        m('pre.head')
        m('mnote', MsgVar=f'Load input file')
        if self.load_file():
            if not self.relay_input:
                self.data_size, self.hash = GetFileInfo(self.input)
                m('proc.input_ok')
        else:
            m('merror', f'Error loading {self.input}', True)
        m('mnote', f'Process input with {self.algorithm.upper()}')
        if hasattr(self, self.algorithm):
            processed_data = getattr(self, self.algorithm)()
        else:
            m('merror', f'Algorithm {self.algorithm} is not valid!', True)
        if processed_data == None:
            m('merror', 'Error while processing data', ErrorExit=True)
        if self.relay_output:
            return processed_data
        else:
            if self.save_file(processed_data):
                self.data_size, self.hash = GetFileInfo(self.output)
                m('proc.out')
            else:
                m('merror', f'Output {self.output} not created!', True)
        m('post.done')

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
            self.msg('mnote', 'Private and/or public key not found, set generate flag...', False)
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
            self.msg('merror', 'Mode not valid, try encode / decode', True)
    
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
