import utils.arg

class uuid_obfuscator:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as UUID strings'
    Version = '1.0.0'
    Shellcode = ''
    Obf_String = ''
    VarCounter = 0
    def init():
        spName = 'uuid'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for UUID encoding'],
            ['-o', '--output', '', '', 'Outputfile for UUID encoding']
        ]
        utils.arg.CreateSubParser(spName, uuid_obfuscator.Description, spArgList)

    def string_to_uuid(string_value):
        formatted_string = f"{string_value[:8]}-{string_value[8:12]}-{string_value[12:16]}-{string_value[16:20]}-{string_value[20:]}"
        return formatted_string
    
    def open_file(filename):
        try:
            for b in open(filename, 'rb').read():
                uuid_obfuscator.Shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False

    def split_string_into_blocks(s, block_size=16):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return [s[i:i + block_size] for i in range(0, len(s), block_size)]
    
    def CreateVar():
        uuid_obfuscator.Obf_String = ''
        blocks = uuid_obfuscator.split_string_into_blocks(uuid_obfuscator.Shellcode, 32)
        uuid_obfuscator.Obf_String = f'std::vector<std::string> sID = '
        uuid_obfuscator.Obf_String += '{\n'
        for block in blocks:
            s = uuid_obfuscator.string_to_uuid(block.decode())
            uuid_obfuscator.Obf_String += f'\"{s}\",\n'
        uuid_obfuscator.Obf_String = uuid_obfuscator.Obf_String[:-2] + ' };'
        return uuid_obfuscator.Obf_String