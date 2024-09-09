import uuid
import qrcode
import qrcode.constants

#from qrcode.image.pure import PyPNGImage

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
    
class obf_qrcode:
    Shellcode = ''
    OutputFilename = ''
    def open_file(filename):
        try:
            for b in open(filename, 'rb').read():
                obf_qrcode.Shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False
            
    def SetOutputFile(outfile):
        #print(f'DBG: {outfile}')
        #if len(outfile) <= 1:
            obf_qrcode.OutputFilename = outfile
        #else:
            #return False
            #exit()
            
    def process():
        qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H)
        payload_bytes = obf_qrcode.Shellcode.encode('utf-8')
        qr.add_data(payload_bytes)
        qr.make(fit=True)
        img = qr.make_image(fill_color='white', back_color='black')
        img.save(obf_qrcode.OutputFilename)


