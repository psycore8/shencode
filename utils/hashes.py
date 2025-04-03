import hashlib

class sha1:
    Author = 'psycore8'
    Description = 'SHA1 Checksum'
    Version = '1.0.1'

    def calculate_sha1(file_path):
        sha1 = hashlib.sha1()
        buffer_size = 65536
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha1.update(chunk)
        return sha1.hexdigest()
