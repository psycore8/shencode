import utils.arg
import qrcode
import qrcode.constants

class qrcode_obfuscator:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as QR-Codes'
    Version = '1.0.0'
    Shellcode = ''
    OutputFilename = ''

    def init():
        spName = 'qrcode'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for QR-Code encoding'],
            ['-o', '--output', '', '', 'Outputfile for QR-Code encoding']
        ]
        utils.arg.CreateSubParser(spName, qrcode_obfuscator.Description, spArgList)

    def open_file(filename):
        try:
            for b in open(filename, 'rb').read():
                qrcode_obfuscator.Shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False
            
    def SetOutputFile(outfile):
        #print(f'DBG: {outfile}')
        #if len(outfile) <= 1:
            qrcode_obfuscator.OutputFilename = outfile
        #else:
            #return False
            #exit()
            
    def process():
        qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H)
        payload_bytes = qrcode_obfuscator.Shellcode.encode('utf-8')
        qr.add_data(payload_bytes)
        qr.make(fit=True)
        img = qr.make_image(fill_color='white', back_color='black')
        img.save(qrcode_obfuscator.OutputFilename)