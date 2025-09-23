########################################################
### QRCode Module
### Status: 086
### 
########################################################

from utils.style import *
from utils.helper import CheckFile, GetFileInfo
from qrcode.image.pure import PyPNGImage
from pyzbar.pyzbar import decode
import cv2
import base64
#import numpy as np
import qrcode
import qrcode.constants

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as QR-Codes'

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
    Version = '2.2.2'
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

    def msg(self, message_type, ErrorExit=False, MsgVar=None):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input_file} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{s_ok} File {self.output_file} created\n{s_ok} Size {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{s_note} Try to generate QR-Code',
            'mnote'          : f'{s_note} {MsgVar}',
            'mok'            : f'{s_ok} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def open_file(self):
        if self.reverse:
            #self.shellcode = cv2.imread(self.input_file)
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
            self.msg('merror', True, 'Base64 encoding error!')

    def base64_str_to_bytes(self, input_string=str) -> bytes:
        try:
            data = base64.b64decode(input_string.encode('ascii'))
            return data
        except:
            self.msg('merror', True, 'Base64 decoding error!')

    def decode_qr_code(self):
        data = cv2.imread(self.input_file)
        #qrDecoder = cv2.QRCodeDetector()
        #qrDecoder.detectAndDecodeBytes
        #dec_data,bbox,rectifiedImage = qrDecoder.detectAndDecode(data)
        dec_data = decode(data)
        #print(dec_data[0].data.decode('utf-8'))
        out_bytes = self.base64_str_to_bytes(dec_data[0].data.decode('utf-8'))
        if len(dec_data)>0:
            #print(dec_data.encode('latin-1'))

            with open(self.output_file, 'wb') as f:
                f.write(out_bytes)
                #f.write(dec_data.encode('latin-1'))
        else:
            print("QR Code not detected")
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
        self.msg('pre.head')
        self.msg('proc.input_try')
        self.open_file()
        #print(self.shellcode[0:10])
        if CheckFile(self.input_file):
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
            if self.reverse:
                self.decode_qr_code()
                if CheckFile(self.output_file):
                    self.data_size, self.hash = GetFileInfo(self.output_file)
                    self.msg('proc.output_ok')
                self.msg('post.done')
                return True
            else:
                if self.check_max_size(self.shellcode):
                    self.msg('mnote', False, 'File size check passed')
                else:
                    self.msg('merror', True, 'File size exceeds 1852 bytes!')
                self.msg('proc.try')
                qr = qrcode.QRCode(image_factory=PyPNGImage, error_correction=qrcode.constants.ERROR_CORRECT_Q)
                #qr = qrcode.QRCode()
                #qr = qrcode.QRCode(version=40, error_correction=qrcode.constants.ERROR_CORRECT_Q)
                #payload_bytes = self.shellcode
                payload_bytes = self.bytes_to_base64_str(self.shellcode)
                print(payload_bytes)
                qr.add_data(payload_bytes)
                qr.make(fit=True)
                #type(img)
                img = qr.make_image(fill_color='white', back_color='black')
                #img = qr.make()
                img.save(self.output_file)
                if CheckFile(self.output_file):
                    self.data_size, self.hash = GetFileInfo(self.output_file)
                    self.msg('proc.output_ok')
                else:
                    self.msg('error.output', True)
        else:
            self.msg('error.input', True)
        self.msg('post.done')