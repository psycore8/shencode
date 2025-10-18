########################################################
### ShenCode Module
###
### Name: MiniDump
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.helper import GetFileInfo
from os import path
from utils.style import *
from utils.windef import *
from utils.winconst import minidumptypes
from yaspin import yaspin
import ctypes
import ctypes.wintypes as wintypes
import threading
import time
import wmi

CATEGORY    = 'core'
DESCRIPTION = 'Create a dump of a running process'

cs = ConsoleStyles()

arglist ={
    'output':               { 'value': None, 'desc': 'Output file' },
    'processname':          { 'value': None, 'desc': 'Processname to dump' },
    'minidumptype':         { 'value': None, 'desc': 'Type of the minidump (default: MiniDumpWithFullMemory)' }
}

def register_arguments(parser):
    parser.add_argument('-o', '--output', required=True, help=arglist['output']['desc'])
    parser.add_argument('-p', '--processname', required=True, help=arglist['processname']['desc'])
    opt = parser.add_argument_group('Optional:')
    opt.add_argument('-m', '--minidumptype', required=False, help=arglist['minidumptype']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'MINIDUMP'
    data_size = int
    hash = ''
    dbghelp = any
    h_file = any
    h_process = any
    data_bytes = bytes
    pid = any
    shell_path = '::core::minidump'

    def __init__(self, output, processname, minidumptype=minidumptypes.MiniDumpWithFullMemory):
        self.output = output
        self.processname = processname
        self.minidumptype = minidumptype

    def get_proc_id(self):
        processes = wmi.WMI().Win32_Process(name=self.processname)
        self.pid = processes[0].ProcessId
        return int(self.pid)
    
    def write_minidump(self):
        MiniDumpWriteDump = self.dbghelp.MiniDumpWriteDump
        MiniDumpWriteDump.argtypes = [
            HANDLE, DWORD, HANDLE, DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        ]
        MiniDumpWriteDump.restype = BOOL
        MiniDumpWriteDump( self.h_process, self.pid, self.h_file, self.minidumptype, None, None, None )
        
    def process(self):
        #m = self.msg
        #m('pre.head')
        cs.module_header(self.DisplayName, self.Version)
        if not self.minidumptype:
            self.minidumptype = minidumptypes.MiniDumpWithFullMemory
        #m('mnote', f'Getting PID from {self.processname}')
        cs.console_print.note(f'Getting PID from {self.processname}')
        result = self.get_proc_id()
        if not result:
            cs.console_print.error(f'Failed to get the PID of {self.processname}')
            #m('merror', f'Failed to get the PID of {self.processname}', True)
        #m('mok', f'PID: {self.pid}')
        cs.console_print.ok(f'PID: {self.pid}')
        cs.console_print.note('Try to receive a process handle')
        #m('mnote', 'Try to receive a process handle')
        self.h_process = ctypes.windll.kernel32.OpenProcess( 0x001F0FFF, False, self.pid )
        if self.h_process == 0:
            cs.console_print.error(f'Failed to get a process handle: {ctypes.get_last_error()}')
            return
            #m('merror', f'Failed to get a process handle: {ctypes.get_last_error()}', True)
        #m('mok', 'Process handle received')
        cs.console_print.ok('Process handle received')
        cs.console_print.note('Try to open the output file')
        #m('mnote', 'Try to open the output file')
        self.h_file = ctypes.windll.kernel32.CreateFileW( self.output, 0x40000000,  0, None, 2, 0, None )
        if self.h_file == -1:
            cs.console_print.error(f'CreateFileW error: {ctypes.get_last_error()}')
            return
            #m('merror', f'CreateFileW error: {ctypes.get_last_error()}', True)
        cs.console_print.ok('File created and writable')
        cs.console_print.note('Load dbghelp.dll')
        #m('mok', 'File created and writable')
        # m('mnote', 'Load dbghelp.dll')
        self.dbghelp = ctypes.windll.LoadLibrary("dbghelp.dll")
        if self.dbghelp == 0:
            cs.console_print.error(f'Error while loading dbghelp.dll: {ctypes.get_last_error()}')
        cs.console_print.ok('dbghelp.dll loaded')
        thread = threading.Thread(target=self.write_minidump)
        thread.start()
        with yaspin(text=" Writing minidump", color="cyan") as spinner:
            while thread.is_alive():
                time.sleep(0.1)
            spinner.ok('✔')
        ctypes.windll.kernel32.CloseHandle(self.h_file)
        ctypes.windll.kernel32.CloseHandle(self.h_process)
        
        cs.action_save_file2(self.output)
        #success = path.exists(self.output)
        #if success:
        #    self.data_size, self.hash = GetFileInfo(self.output)
        #    m('proc.out')
        #else:
        #    m('merror', f'Error writing dump: {ctypes.get_last_error()}', True)
        #m('post.done')
        cs.console_print.ok('DONE!')

        



