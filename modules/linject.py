########################################################
### ShenCode Module
###
### Name: Linject
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import ctypes
import mmap

from utils.helper import CheckFile, GetFileInfo
from utils.style import *

CATEGORY    = 'inject'
DESCRIPTION = 'Linux based injection module'

cs = ConsoleStyles()

arglist = {
    'input':            { 'value': None, 'desc': 'Input file for injection' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])


class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'LiNUX-iNJECTER'
    relay_input = False
    shell_path = '::inject::linject'
    data_size = 0
    hash = ''
    shellcode = any

    def __init__(self, input):
        self.input = input

    def start_injection(self):
        buf = mmap.mmap(-1, len(self.shellcode), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        buf.write(self.shellcode)
        ctypes_buffer = ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf)))
        func_type = ctypes.CFUNCTYPE(None)
        func = func_type(ctypes_buffer.value)
        cs.print('Execute shellcode...', cs.state_note)
        func()

    def open_file(self):
        try:
            with open(self.input, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        if isinstance(self.input, str):
            if CheckFile(self.input):
                cs.action_open_file2(self.input)
            else:
                cs.print('File not found!', cs.state_fail)
                return
            self.open_file()
            self.start_injection()
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            self.start_injection()
        cs.print('DONE!', cs.state_ok)
