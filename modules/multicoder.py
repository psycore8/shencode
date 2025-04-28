########################################################
### MultiCODER Module
### Status: dev
### 
########################################################

import base64
import os

from utils.helper import nstate
from utils.helper import GetFileInfo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CATEGORY    = 'dev'
DESCRIPTION = 'En- / Decoder for different algorithms. Supports: base32, base64'

def register_arguments(parser):
    parser.add_argument('-a', '--algorithm' ,choices=['base32', 'base64'], required=True, help='')
    parser.add_argument('-m', '--mode', choices=['encode', 'decode'], required=True, help='Operation mode, choose encode / decode')
    parser.add_argument('-i', '--input', required=True, help='Input file')
    parser.add_argument('-k', '--key', required=False, default=None, help='If required, set the en- / decryption key')
    parser.add_argument('-o', '--output', required=True, help= 'Output file')

class module:
    Author = 'psycore8'
    Version = '0.0.2'
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
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',
            'error.enc'      : f'{nstate.s_fail} En-/Decrption error, aborting script execution',
            'error.mode'     : f'{nstate.s_fail} Please provide a valid mode: encode / decode',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_info} Size of shellcode {self.data_size} bytes\n{nstate.s_info} Hash: {self.hash}',
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
        m('mnote', f'Process input with {self.algorithm}')
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
    
    def generate_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit Schlüssel
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def aes(self):
        if self.mode == 'encode':
            pass
        elif self.mode == 'decode':
            salt, iv = None
        else:
            processed_data = None
        return processed_data, salt, iv

    def aes_encrypt(self, data: bytes, password: bytes):
        salt, iv = os.urandom(16)
        #iv = os.urandom(16)
        key = self.generate_key(password, salt)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, salt, iv
    
    def aes_decrypt(self, encrypted_data: bytes, password: bytes, salt: bytes, iv: bytes) -> bytes:
        key = self.generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data