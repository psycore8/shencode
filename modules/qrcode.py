from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from qrcode.image.pure import PyPNGImage
import qrcode
import qrcode.constants

CATEGORY = 'obfuscate'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for QR-Code encoding')
    parser.add_argument('-o', '--output', help='Output file for QR-Code encoding')

class module:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as QR-Codes'
    Version = '2.1.2'
    DisplayName = 'QRCODE-OBF'
    hash = ''
    data_size = 0

    def __init__(self, input_file, output_file, shellcode):
         self.input_file = input_file
         self.output_file = output_file
         self.shellcode = shellcode

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{nstate.s_note} Try to generate generate QR-Code',
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def open_file(self):
        try:
            for b in open(self.input_file, 'rb').read():
                self.shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False
                        
    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        self.open_file()
        if CheckFile(self.input_file):
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
            self.msg('proc.try')
            qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H, image_factory=self.PyPNGImage)
            payload_bytes = self.shellcode.encode('utf-8')
            qr.add_data(payload_bytes)
            qr.make(fit=True)
            img = qr.make_image(fill_color='white', back_color='black')
            img.save(self.output_file)
            if CheckFile(self.output_file):
                self.data_size, self.hash = GetFileInfo(self.output_file)
                self.msg('proc.output_ok')
            else:
                self.msg('error.output', True)
        else:
            self.msg('error.input', True)
        self.msg('post.done')