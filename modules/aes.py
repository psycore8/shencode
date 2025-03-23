from utils.helper import nstate as nstate
from utils.helper import GetFileHash #, CheckFile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import pickle
import os

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-m', '--mode', choices=['encode', 'decode'], required=True, help='AES Operation mode, choose between encode and decode')
    parser.add_argument('-i', '--input', required=True, help='Input file for AES encoding')
    parser.add_argument('-k', '--key', required=True, help='Key for AES encoding')
    parser.add_argument('-o', '--output', required=True, help= 'Outputfile for AES encoding')

class module:
    Author = 'psycore8'
    Description = 'AES encoder for payloads'
    Version = '2.1.1'
    DisplayName = 'AES-ENCODER'
    data_size = int
    hash = ''

    def __init__(self, mode, input_file, output_file, key, data_bytes:bytes):
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.key = key
        self.data_bytes = data_bytes

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.enc'      : f'{nstate.s_fail} En-/Decrption error, aborting script execution',
            'error.mode'     : f'{nstate.s_fail} Please provide a valid mode: encode / decode',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.out'       : f'{nstate.s_ok} File created in {self.output_file}\n{nstate.s_ok} Hash: {self.hash}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def generate_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit Schlüssel
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
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
        cipher = Cipher(self.algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data
    
    def EncodeKey(self):
        self.key = self.key.encode('utf-8')
    
    def encode(self):
        try:
            with open(self.input_file, 'rb') as file:
                self.data_bytes = file.read()
        except FileNotFoundError:
            self.msg('error.input', True)
            #print(f'{nstate.FAIL} File {self.input_file} not found or cannot be opened.')
            #exit()
        self.data_size = len(self.data_bytes)
        self.hash = GetFileHash(self.input_file)
        self.msg('proc.input_ok')
        #print(f'{nstate.OKBLUE} File {self.input_file} loaded, size of shellcode {size} bytes')
        enc_data, salt, iv = self.aes_encrypt(self.data_bytes, self.key)
        with open(self.output_file, "wb") as f:
            pickle.dump((enc_data, salt, iv), f)
        cf = os.path.isfile(self.output_file)
        if cf == True:
            self.hash = GetFileHash(self.output_file)
            self.msg('proc.out')
            #print(f"{nstate.OKGREEN} [AES-ENC] file created in {self.output_file}")
        else:
            self.msg('error.input', True)
            #print(f"{nstate.FAIL} [AES-ENC] encrption error, aborting script execution")
            #exit()

    def decode(self):
        enc_data = b''
        salt = 0
        iv = 0
        try:
            with open(self.input_file, "rb") as f:
                enc_data, salt, iv = pickle.load(f)
        except FileNotFoundError:
            self.msg('error.input', True)
        self.data_size = len(enc_data)
        self.hash = GetFileHash(self.input_file)
        self.msg('proc.input_ok')
        #print(f'{nstate.OKBLUE} File {self.input_file} loaded, filesize {size} bytes')
        Shellcode = self.aes_decrypt(enc_data, self.key, salt, iv)
        with open(self.output_file, 'wb') as file:
             file.write(Shellcode)
        cf = os.path.isfile(self.output_file)
        if cf == True:
            self.hash = GetFileHash(self.output_file)
            self.msg('proc.out')
            #print(f"{nstate.OKGREEN} [AES-DEC] file created in {self.output_file}")
        else:
            self.msg('error.input', True)
            #print(f"{nstate.FAIL} [AES-DEC] encrption error, aborting script execution")
            #exit()

    def process(self):
        self.msg('pre.head')
        self.EncodeKey()
        if self.mode == 'encode':
            self.encode()
        elif self.mode == 'decode':
            self.decode()
        else:
            self.msg('error.mode', True)
        self.msg('post.done')

    # def debug():
    #     aes_encoder.Input_File = 'dev\\aes-debug-plain.txt'
    #     aes_encoder.Output_File = 'dev\\aes-debug-crypt.txt'
    #     file_processing = 'dev\\aes-debug-final.txt'
    #     aes_encoder.Password = b'debugger'
    #     data = b'SecretText'

    #     crypted_data, salt, iv = aes_encoder.aes_encrypt(data, aes_encoder.Password)

    #     print(f'AES Data: {crypted_data}')
    #     print(f'AES Salt: {salt}')
    #     print(f'AES IV: {iv}')

    #     decrypted_data = aes_encoder.aes_decrypt(crypted_data, aes_encoder.Password, salt, iv)

    #     print(f'AES Plaim: {decrypted_data}')