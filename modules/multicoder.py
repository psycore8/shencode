########################################################
### MultiCODER Module
### Status: dev
### 
########################################################

import base64
import os
import pickle

from utils.helper import nstate
from utils.helper import GetFileInfo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CATEGORY    = 'dev'
DESCRIPTION = 'En- / Decoder for different algorithms. Supports: AES, Base32, Base64, RSA'

def register_arguments(parser):
    parser.add_argument('-a', '--algorithm' ,choices=['base32', 'base64', 'aes', 'rsa'], required=True, help='')
    parser.add_argument('-m', '--mode', choices=['encode', 'decode'], required=True, help='Operation mode, choose encode / decode')
    parser.add_argument('-i', '--input', required=True, help='Input file')
    parser.add_argument('-k', '--key', required=False, default=None, help='If required, set the en- / decryption key')
    parser.add_argument('-o', '--output', required=True, help= 'Output file')

    rsa = parser.add_argument_group('RSA arguments:')
    rsa.add_argument('--gen-keys', action='store_true', default=False, help='Generate a key pair')
    rsa.add_argument('--key-file', default='', help='Key to decode')
    rsa.add_argument('--priv-key', default='', help='Private key file')
    rsa.add_argument('--pub-key', default='', help='Public key file')

class module:
    Author = 'psycore8'
    Version = '0.0.5'
    DisplayName = 'MultiC0DER'
    data_size = int
    hash = ''
    data_bytes = bytes
    relay_input = False
    relay_output = False

    def __init__(self, algorithm, mode, input, key, output, gen_keys, key_file, priv_key, pub_key):
        self.algorithm = algorithm
        self.mode = mode
        self.input = input
        self.key = key
        self.output = output
        if self.algorithm == 'rsa':
            self.gen_keys = gen_keys
            self.key_file = key_file
            self.priv_key = priv_key
            self.pub_key = pub_key
        

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
        #rsa_cryptkey = f'{fn_root}.key'
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from utils.crypt import rsa_worker
        rw = rsa_worker()
        fn_root, fn_extension = os.path.splitext(self.output)
        key_file = f'{fn_root}.key'
        if self.gen_keys:
            rsa_privkey = f'{fn_root}_private.pem'
            rsa_pubkey = f'{fn_root}_public.pem'
            # private_key = rsa.generate_private_key(
            #     public_exponent=65537,
            #     key_size=2048
            # )
            rw.generate_key_pair()
            rw.save_key_pair(rsa_privkey, rsa_pubkey)
            # public_key = private_key.public_key()
            # with open(rsa_privkey, "wb") as f:
            #     f.write(private_key.private_bytes(
            #         encoding=serialization.Encoding.PEM,
            #         format=serialization.PrivateFormat.PKCS8,
            #         encryption_algorithm=serialization.NoEncryption()
            #     ))
            # with open(rsa_pubkey, "wb") as f:
            #     f.write(public_key.public_bytes(
            #         encoding=serialization.Encoding.PEM,
            #         format=serialization.PublicFormat.SubjectPublicKeyInfo
            #     ))
        else:
            if self.mode == 'decode':
                # with open(self.priv_key, 'rb') as f:
                #     private_key = serialization.load_pem_private_key(
                #         f.read(),
                #         password=None,  # Falls dein Schlüssel passwortgeschützt ist, gib hier das Passwort als bytes an
                #         backend=default_backend()
                #     )
                rw.load_private_key(self.priv_key)
            else:
                # with open(self.pub_key, 'rb') as f:
                #     public_key = serialization.load_pem_public_key(
                #         f.read(),
                #         password=None,
                #         backend=default_backend()
                #     )
                rw.load_public_key(self.pub_key)
            #private_key = self.priv_key
            #public_key = self.pub_key
        if self.mode == 'encode':
            processed_data = self.aes()
            ciphertext = self.public_key.encrypt(
                self.key.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            with open(key_file, 'wb') as f:
                f.write(ciphertext)
            return processed_data
        elif self.mode == 'decode':
            with open(self.key_file, 'rb') as f:
                masterkey = f.read()
            decrypted = self.private_key.decrypt(
                masterkey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.key = decrypted.decode('utf-8')
            processed_data = self.aes()
            return processed_data
        else:
            self.msg('merror', 'Mode not valid, try encode / decode', True)

    def generate_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def aes(self):
        if self.mode == 'encode':
            buffer, salt, iv = self.aes_encrypt(self.data_bytes, self.key.encode('utf-8'))
            processed_data = pickle.dumps((buffer, salt, iv))
        elif self.mode == 'decode':
            buffer, salt, iv = pickle.loads(self.data_bytes)
            processed_data = self.aes_decrypt(buffer, self.key.encode('utf-8'), salt, iv)
        else:
            processed_data = None
        return processed_data

    def aes_encrypt(self, data: bytes, password: bytes):
        salt = os.urandom(16)
        iv = os.urandom(16)
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