import hashlib

class sha1:

    def calculate_sha1(file_path):
        sha1 = hashlib.sha1()
        buffer_size = 65536
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha1.update(chunk)
        return sha1.hexdigest()
    
class FunctionHash:

    def __init__(self):
        pass

    def unicode(self, string, uppercase=True):
        result = ''
        if uppercase:
            string = string.upper()
        for c in string + '\x00':
            result += c
        return result

    def ror32(self, val, r_bits):
        return ((val >> (r_bits%32)) | (val << (32-(r_bits%32)))) & 0xffffffff

    def ror_hash(self, api_name: str, shift_right_bits: int) -> int:
        hash = 0
        for c in api_name:
            hash = self.ror32(hash, shift_right_bits)
            hash += ord(c)
            #print(f'Ordinal: {ord(c)}')
            #print(f'Hash: {hex(hash)}')        
        hash = hash & 0xFFFFFFFF
        return hash

    def rol32(val, l_bits):
        return ((val << l_bits) | (val >> (32 - l_bits))) & 0xFFFFFFFF

    def rol_hash(self, api_name: str, shift_left_bits: int) -> int:
        hash = 0
        for c in api_name:
            hash = self.rol32(hash, shift_left_bits)
            hash += ord(c)
            #print(f'Ordinal: {ord(c)}')
            #print(f'Hash: {hex(hash)}')        
        hash = hash & 0xFFFFFFFF
        return hash