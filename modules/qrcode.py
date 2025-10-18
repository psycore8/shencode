########################################################
### ShenCode Module
###
### Name: QRCode
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.helper import CheckFile
from qrcode.image.pure import PyPNGImage
from pyzbar.pyzbar import decode
import cv2
import base64
import qrcode
import qrcode.constants

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as QR-Codes'

cs = ConsoleStyles()

arglist = {
    'input':        { 'value': None, 'desc': 'Input file for QR-Code encoding' },
    'output':       { 'value': None, 'desc': 'Output file for QR-Code encoding' },
    'reverse':      { 'value': None, 'desc': 'Reads data from QR code image' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])
    parser.add_argument('-o', '--output', help=arglist['output']['desc'])
    parser.add_argument('-r', '--reverse', action='store_true', help=arglist['reverse']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'QRCODE-OBF'
    hash = ''
    data_size = 0
    shellcode = b''
    relay_input = False
    shell_path = '::obfuscate::qrcode'

    def __init__(self, input, output, reverse):
         self.input_file = input
         self.output_file = output
         self.reverse = reverse

    def open_file(self):
        if self.reverse:
            return True
        if self.relay_input:
            self.shellcode = self.input_file
        else:
            try:
                with open(self.input_file, 'rb') as f:
                    self.shellcode = f.read()
                return True
            except FileNotFoundError:
                return False
            
    def display(self, im, bbox):
        n = len(bbox)
        for j in range(n):
            cv2.line(im, tuple(bbox[j][0]), tuple(bbox[ (j+1) % n][0]), (255,0,0), 3)
        cv2.imshow("Results", im)

    def bytes_to_base64_str(self, input_bytes=bytes) -> str:
        try:
            data = base64.b64encode(input_bytes).decode('ascii')
            return data
        except:
            cs.console_print.error('Base64 encoding error!')
            return

    def base64_str_to_bytes(self, input_string=str) -> bytes:
        try:
            data = base64.b64decode(input_string.encode('ascii'))
            return data
        except:
            cs.console_print.error('Base64 decoding error!')
            return

    def decode_qr_code(self):
        data = cv2.imread(self.input_file)
        dec_data = decode(data)
        out_bytes = self.base64_str_to_bytes(dec_data[0].data.decode('utf-8'))
        if len(dec_data)>0:
            with open(self.output_file, 'wb') as f:
                f.write(out_bytes)
        else:
            cs.console_print.error('QR Code not detected')
            cv2.imshow("Results", dec_data)
        
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    def check_max_size(self, input):
        # Max size depends on error correction level:
        # Low ~7%:          2953 Bytes
        # Medium ~15%:      2331 Bytes
        # Quartile ~25%:    1852 Bytes
        # High ~30%:        1273 Bytes
        length = len(input)
        max_size = 1852
        if length <= max_size:
            return True
        else: 
            return False

                        
    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        cs.console_print.note('Try to open file')
        self.open_file()
        if CheckFile(self.input_file):
            cs.action_open_file2(self.input_file)
            if self.reverse:
                self.decode_qr_code()
                cs.action_save_file2(self.output_file)
                cs.console_print.ok('DONE!')
                return True
            else:
                if self.check_max_size(self.shellcode):
                    cs.console_print.note('File size check passed')
                else:
                    cs.console_print.error('File size exceeds 1852 bytes')
                    return
                cs.console_print.note('Try to generate QR Code')
                qr = qrcode.QRCode(image_factory=PyPNGImage, error_correction=qrcode.constants.ERROR_CORRECT_Q)
                payload_bytes = self.bytes_to_base64_str(self.shellcode)
                qr.add_data(payload_bytes)
                qr.make(fit=True)
                img = qr.make_image(fill_color='white', back_color='black')
                img.save(self.output_file)
                cs.action_save_file2(self.output_file)
        else:
            cs.console_print.error('File not found or cannot be opened')
            return
        cs.console_print.ok('DONE!')
