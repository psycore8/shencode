

CATEGORY = 'obfuscate'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for UUID encoding')

class uuid_obfuscator:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as UUID strings'
    Version = '2.0.0'

    def __init__(self, input_file, shellcode, obf_string, var_counter):
        self.input_file = input_file
        self.shellcode = shellcode
        self.obf_string = obf_string
        self.var_counter = var_counter

    def string_to_uuid(self, string_value):
        formatted_string = f"{string_value[:8]}-{string_value[8:12]}-{string_value[12:16]}-{string_value[16:20]}-{string_value[20:]}"
        return formatted_string
    
    def open_file(self, filename):
        try:
            for b in open(filename, 'rb').read():
                self.shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False

    def split_string_into_blocks(self, s, block_size=16):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return [s[i:i + block_size] for i in range(0, len(s), block_size)]
    
    def CreateVar(self):
        self.Obf_String = ''
        blocks = self.split_string_into_blocks(self.shellcode, 32)
        self.obf_string = f'std::vector<std::string> sID = '
        self.obf_string += '{\n'
        for block in blocks:
            s = self.string_to_uuid(block.decode())
            self.obf_string += f'\"{s}\",\n'
        self.obf_string = self.obf_string[:-2] + ' };'
        return self.obf_string