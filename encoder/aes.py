import utils.arg
from utils.helper import nstate as nstate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import pickle
import os

class aes_encoder:
    Author = 'psycore8'
    Description = 'AES encoder for payloads'
    Version = '1.0.0'
    Input_File = ''
    Output_File = ''
    Password = b''
    DataBytes = b''

    def init():
        spName = 'aesenc'
        spArgList = [
          ['-m', '--mode', 'encode,decode', '', 'AES Operation mode, choose between encode and decode'],
          ['-i', '--input', '', '', 'Input file for AES encoding'],
          ['-o', '--output', '', '', 'Outputfile for AES encoding'],
          ['-k', '--key', '', '', 'Key for AES encoding'],
          ['-debug', '--debug', '', 'store_true', 'debug']
        ]
        utils.arg.CreateSubParser(spName, aes_encoder.Description, spArgList)

    def generate_key(password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit Schlüssel
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def aes_encrypt(data: bytes, password: bytes) -> (bytes, bytes, bytes):
        # Salt und Initialisierungsvektor (IV) generieren
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = aes_encoder.generate_key(password, salt)

        # Paddings für Blockgröße (AES Blockgröße = 128 Bit)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # AES-Cipher im CBC-Modus
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data, salt, iv
    
    def aes_decrypt(encrypted_data: bytes, password: bytes, salt: bytes, iv: bytes) -> bytes:
        key = aes_encoder.generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Padding entfernen
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data
    
    def encode():
        outputfile = aes_encoder.Output_File
        inputfile = aes_encoder.Input_File
        password = aes_encoder.Password
        try:
            with open(inputfile, 'rb') as file:
                aes_encoder.DataBytes = file.read()
        except FileNotFoundError:
            print(f'{nstate.FAIL} File {aes_encoder.Input_File} not found or cannot be opened.')
            exit()
        size = len(aes_encoder.DataBytes)
        print(f'{nstate.OKBLUE} File {aes_encoder.Input_File} loaded, size of shellcode {size} bytes')
        enc_data, salt, iv = aes_encoder.aes_encrypt(aes_encoder.DataBytes, password)
        #print(f'{AESData}')
        with open(outputfile, "wb") as f:
            pickle.dump((enc_data, salt, iv), f)
        # with open(outputfile, 'wb') as file:
        #     file.write(AESData)
        path = outputfile
        cf = os.path.isfile(path)
        if cf == True:
            print(f"{nstate.OKGREEN} AES encrypted shellcode created in {outputfile}")
        else:
            print(f"{nstate.FAIL} AES encrption error, aborting script execution")
            exit()

    def decode():
        outputfile = aes_encoder.Output_File
        inputfile = aes_encoder.Input_File
        password = aes_encoder.Password
        enc_data = b''
        salt = 0
        iv = 0
        try:
            with open(inputfile, "rb") as f:
                #AESData[0], AESData[1], AESData[2] = pickle.load(f)
                enc_data, salt, iv = pickle.load(f)
        except FileNotFoundError:
            print(f'{nstate.FAIL} File {inputfile} not found or cannot be opened.')
            exit()
        size = len(enc_data)
        print(f'{nstate.OKBLUE} File {inputfile} loaded, filesize {size} bytes')
        Shellcode = aes_encoder.aes_decrypt(enc_data, password, salt, iv)
        #AESData = aes_encoder.aes_encrypt(aes_encoder.DataBytes, password)
        #print(f'{AESData}')
        #with open(outputfile, "wb") as f:
        #    pickle.dump((AESData[0], AESData[1], AESData[2]), f)
        with open(outputfile, 'wb') as file:
             file.write(Shellcode)
        path = outputfile
        cf = os.path.isfile(path)
        if cf == True:
            print(f"{nstate.OKGREEN} AES encrypted shellcode created in {outputfile}")
        else:
            print(f"{nstate.FAIL} AES encrption error, aborting script execution")
            exit()

    def debug():
        aes_encoder.Input_File = 'dev\\aes-debug-plain.txt'
        aes_encoder.Output_File = 'dev\\aes-debug-crypt.txt'
        file_processing = 'dev\\aes-debug-final.txt'
        aes_encoder.Password = b'debugger'
        data = b'SecretText'

        crypted_data, salt, iv = aes_encoder.aes_encrypt(data, aes_encoder.Password)

        print(f'AES Data: {crypted_data}')
        print(f'AES Salt: {salt}')
        print(f'AES IV: {iv}')

        decrypted_data = aes_encoder.aes_decrypt(crypted_data, aes_encoder.Password, salt, iv)

        print(f'AES Plaim: {decrypted_data}')