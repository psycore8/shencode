import base64
from itertools import cycle

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR encoding')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR encoding')
    parser.add_argument('-k', '--key', help='Key for XOR encoding')

class xor_encoder:
    Author = 'psycore8'
    Description = 'XOR encoder for payloads'
    Version = '2.0.0'

    def __init__(self, input_file, output_file, xor_key):
        self.input_file = input_file
        self.output_file = output_file
        self.xor_key = xor_key

    def xor_crypt_string(data, key, encode = False, decode = False):
        if decode:
            data_bytes = base64.b64decode(data)
            data = data_bytes.decode("utf-8")
        xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
   
        if encode:
            data_bytes = base64.b64encode(xored.encode("utf-8"))
            return data_bytes.decode("utf-8")
        return xored
   
    def xor_crypt_bytes(self, data, key):
        out = [x ^ key for x in data]
        print(out)
        return bytes(out)