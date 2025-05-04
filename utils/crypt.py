class rsa_worker:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.RSAPrivateKey
        public_key = rsa.RSAPublicKey

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
                        return True
                except:
                       return False
                try:
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
                        backend=self.default_backend()
                    )

        def load_public_key(self, public_key_file):
                with open(public_key_file, 'rb') as f:
                    self.public_key = self.serialization.load_pem_public_key(
                        f.read(),
                        password=None,
                        backend=self.default_backend()
                    )