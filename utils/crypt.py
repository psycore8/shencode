from cryptography.hazmat.backends import default_backend

class rsa_worker:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization


        private_key = rsa.RSAPrivateKey
        public_key = rsa.RSAPublicKey
        encrypted_data = b''
        decrypted_data = b''

        def __init__(self):
                self = self

        def generate_key_pair(self, public_exponent=65537, key_size=4096):
                self.private_key = self.rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
                self.public_key = self.private_key.public_key()

        def save_key_pair(self, private_key_file, public_key_file):
                try:
                    with open(private_key_file, 'wb')as f:
                        f.write(self.private_key.private_bytes(
                            encoding=self.serialization.Encoding.PEM,
                            format=self.serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=self.serialization.NoEncryption()
                        ))
                    with open(public_key_file, 'wb') as f:
                        f.write(self.public_key.public_bytes(
                            encoding=self.serialization.Encoding.PEM,
                            format=self.serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
                    return True
                except:
                       return False
                
        def load_private_key(self, private_key_file):
                with open(private_key_file, 'rb') as f:
                    self.private_key = self.serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )

        def load_public_key(self, public_key_file):
                with open(public_key_file, 'rb') as f:
                    self.public_key = self.serialization.load_pem_public_key(
                        f.read(),
                        #password=None,
                        backend=default_backend()
                    )

        def rsa_encrypt(self, plaintext_key:bytes):
           self.encrypted_data = self.public_key.encrypt(
                            plaintext_key,
                            self.padding.OAEP(
                                mgf=self.padding.MGF1(algorithm=self.hashes.SHA256()),
                                algorithm=self.hashes.SHA256(),
                                label=None
                            )
                        )
           
        def rsa_decrypt(self)->str:
            self.decrypted_data = self.private_key.decrypt(
                        self.encrypted_data,
                        self.padding.OAEP(
                            mgf=self.padding.MGF1(algorithm=self.hashes.SHA256()),
                            algorithm=self.hashes.SHA256(),
                            label=None
                        )
                    )
            return self.decrypted_data.decode('utf-8')

        def save_encrypted_key(self, encrypted_key_file):
                try:
                    with open(encrypted_key_file, 'wb') as f:
                          f.write(self.encrypted_data)
                    return True
                except:
                      return False
                
        def load_encrypted_key(self, encrypted_key_file):
                try:
                    with open(encrypted_key_file, 'rb') as f:
                          self. encrypted_data = f.read()
                except:
                    return False
           
class aes_worker:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from os import urandom

    def generate_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = self.PBKDF2HMAC(
            algorithm=self.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def aes_encrypt(self, data: bytes, password: bytes):
        salt = self.urandom(16)
        iv = self.urandom(16)
        key = self.generate_key(password, salt)
        padder = self.padding.PKCS7(self.algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, salt, iv
    
    def aes_decrypt(self, encrypted_data: bytes, password: bytes, salt: bytes, iv: bytes) -> bytes:
        key = self.generate_key(password, salt)
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = self.padding.PKCS7(self.algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data