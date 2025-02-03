#import utils.arg
import qrcode
import qrcode.constants

CATEGORY = 'obfuscate'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for QR-Code encoding')
    parser.add_argument('-o', '--output', help='Outputfile for QR-Code encoding')

class qrcode_obfuscator:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as QR-Codes'
    Version = '2.0.0'

    def __init__(self, input_file, output_file, shellcode):
         self.input_file = input_file
         self.output_file = output_file
         self.shellcode = shellcode

    # def init():
    #     spName = 'qrcode'
    #     spArgList = [
    #         ['-i', '--input', '', '', 'Input file for QR-Code encoding'],
    #         ['-o', '--output', '', '', 'Outputfile for QR-Code encoding']
    #     ]
    #     utils.arg.CreateSubParser(spName, qrcode_obfuscater.Description, spArgList)

    def open_file(self):
        try:
            for b in open(self.input_file, 'rb').read():
                self.shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False
            
    #def SetOutputFile(outfile):
    #        qrcode_obfuscator.OutputFilename = outfile
            
    def process(self):
        qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H)
        payload_bytes = self.shellcode.encode('utf-8')
        qr.add_data(payload_bytes)
        qr.make(fit=True)
        img = qr.make_image(fill_color='white', back_color='black')
        img.save(self.output_file)