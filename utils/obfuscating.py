import uuid

class obf_uuid:
    Shellcode = ''
    Obf_String = ''
    VarCounter = 0
    def string_to_uuid(string_value):
        formatted_string = f"{string_value[:8]}-{string_value[8:12]}-{string_value[12:16]}-{string_value[16:20]}-{string_value[20:]}"
        return formatted_string
    
    def open_file(filename):
        try:
            for b in open(filename, 'rb').read():
                obf_uuid.Shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False

    def split_string_into_blocks(s, block_size=16):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return [s[i:i + block_size] for i in range(0, len(s), block_size)]
    
    def CreateVar():
        obf_uuid.Obf_String = ''
        blocks = obf_uuid.split_string_into_blocks(obf_uuid.Shellcode, 32)
        obf_uuid.Obf_String = f'std::vector<std::string> sID = '
        obf_uuid.Obf_String += '{\n'
        for block in blocks:
            s = obf_uuid.string_to_uuid(block.decode())
            obf_uuid.Obf_String += f'\"{s}\",\n'
        obf_uuid.Obf_String = obf_uuid.Obf_String[:-2] + ' };'
        return obf_uuid.Obf_String

