########################################################
### ShenCode Module
###
### Name: AlphaNum Encoder
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import os
import random
import tqdm
from utils.asm import variable_instruction_set
from os import path as osp
from rich.console import Console
from utils.style import *
from utils.const import *
from utils.binary import get_coff_section
from subprocess import run

CATEGORY    = 'encoder'
DESCRIPTION = 'Encode bytes to alphanumeric output'

cs = ConsoleStyles()

arglist = {
    'input':                { 'value': None,    'desc': 'Input file to use' },
    'output':               { 'value': None,    'desc': 'Output file to use' },
    'decode':               { 'value': False,   'desc': 'Decode the input to bytes' },
    'compile':              { 'value': False,   'desc': 'Compile object file and extract shellcode' },
    'variable_padding':     { 'value': False,   'desc': 'Inserts random NOPs to differ the padding' },
}

def register_arguments(parser):
            parser.add_argument('-i', '--input', help=arglist['input']['desc'])
            parser.add_argument('-o', '--output', help=arglist['output']['desc'])

            add = parser.add_argument_group('Additional')
            add.add_argument('-c', '--compile', default=False, action='store_true' ,help=arglist['compile']['desc'])
            add.add_argument('-d', '--decode', default=False, action='store_true' ,help=arglist['decode']['desc'])
            add.add_argument('-v', '--variable-padding', type=int, help=arglist['variable_padding']['desc'])

class module:
    out = Console()
    Author          = 'psycore8'
    Version         = '0.9.0'
    DisplayName     = 'AlphaNum'
    shellcode       = b''
    encoded_data    = ''
    relay_input     = False
    relay_output    = False
    shell_path      = '::encoder::alphanum'

    def __init__(self, input, output, decode=False, compile=False, variable_padding=0):
            self.input = input
            self.output = output
            self.decode = decode
            self.compile = compile
            self.compiler_cmd = nasm
            if variable_padding == None:
                variable_padding = 0
            self.variable_padding = variable_padding

    def CheckNasm(self)->bool:
        if osp.exists(self.compiler_cmd):
            return True
        else:
            return False

    def to_alphanum(self, encoded_shellcode):
        cs.print('Encoder running...', cs.state_note)
        alphanum_shellcode = ''
        for hex_byte in tqdm.tqdm (encoded_shellcode.split('\\x')[1:], colour='magenta'):
            num = int(hex_byte, 16)
            high = (num >> 4) + 0x41  # A-Z (65-90)
            low = (num & 0xF) + 0x61  # a-p (97-112)
            alphanum_shellcode += chr(high) + chr(low)
        return alphanum_shellcode
    
    def from_alphanum(self, alphanum_shellcode):
        cs.print('Decoder running...', cs.state_note)
        if len(alphanum_shellcode) % 2 != 0:
            raise ValueError('Alphanumeric chars not valid!')

        decoded_bytes = bytearray()

        for i in range(0, len(alphanum_shellcode), 2):
            high_char, low_char = alphanum_shellcode[i], alphanum_shellcode[i + 1]

            if not ('A' <= high_char <= 'Z') or not ('a' <= low_char <= 'p'):
                raise ValueError(f'Char combination not valid: {high_char}{low_char}')

            high = ord(high_char) - 0x41  # A-Z → High-Nibble
            low = ord(low_char) - 0x61    # a-p → Low-Nibble
            decoded_byte = (high << 4) | low

            decoded_bytes.append(decoded_byte)

        return bytes(decoded_bytes)
    
    def gen_x64_stub(self):
        vi = variable_instruction_set()
        reg1, reg2, reg3, reg4, reg5 = vi.random.sample(vi.multi_bit_registers, 5)

        #inst_asm_reg_zero = ['xor', 'sub']
        #inst_asm_jmp_cond = ['jz', 'je']
        inst_asm_jmp_ncond = ['jnz', 'jne']
        inst_asm_inc_reg = [
            f'inc {reg5[0]}',
            f'add {reg5[0]}, 1',
            f'lea {reg5[0]}, [{reg5[0]}+1]'
            ]
        inst_asm_dec_reg = [
            f'dec {reg2[0]}',
            f'sub {reg2[0]}, 1',
            f'lea {reg2[0]}, [{reg2[0]}-1]'
            ]
        
        rc = random.choice
        #asm_reg_zero    = random.choice(inst_asm_reg_zero)
        #asm_jmp_cond    = random.choice(inst_asm_jmp_cond)
        #asm_jmp_ncond   = random.choice(inst_asm_jmp_ncond)
        asm_inc_reg     = random.choice(inst_asm_inc_reg)
        asm_dec_reg     = random.choice(inst_asm_dec_reg)

        size = len(self.encoded_data)//2
        if size <= 255:
           sc_size = f'mov {reg2[3]}, {size}'
        elif size <= 65535:
           sc_size = f'mov {reg2[2]}, {size}'
        else:
           sc_size = f'mov {reg2[1]}, {size}'

        stub = f"""
                    section .text
                        global _start

                    _start:
                        {rc(vi.register_set_zero)} {reg1[0]}, {reg1[0]}
                        {rc(vi.register_set_zero)} {reg2[0]}, {reg2[0]}
                        {rc(vi.register_set_zero)} {reg3[0]}, {reg3[0]}
                        {rc(vi.register_set_zero)} {reg4[0]}, {reg4[0]}
                        {rc(vi.register_set_zero)} {reg5[0]}, {reg5[0]}
                        jmp short call_decoder

                    decoder:
                        pop {reg1[0]}                     ; shellcode address = reg1
                        mov {reg5[0]}, {reg1[0]}          ; Target address = reg5
                        {sc_size}                         ; amount of bytes to encode = reg2

                    decode_loop:
                        test {reg2[0]}, {reg2[0]}         ; test reg2
                        {rc(vi.jump_conditional_positive)} encoded_shellcode

                        mov {reg3[3]}, byte [{reg1[0]}]   ; get alphanumeric bytes = reg3
                        sub {reg3[3]}, 0x41               ; "A-Z" → High-Nibble (A=0)
                        shl {reg3[3]}, 4                  ; shift High-Nibble left

                        mov {reg4[3]}, byte [{reg1[0]}+1] ; Low-Nibble = reg4
                        sub {reg4[3]}, 0x61               ; "a-p" → Low-Nibble (a=0)
                        or {reg3[3]}, {reg4[3]}           ; combine high and low nibble

                        mov byte [{reg5[0]}], {reg3[3]}   ; write decoded byte at the same position
                        {rc(inst_asm_inc_reg)}
                        add {reg1[0]}, 2                  ; jump 2 chars
                        {rc(inst_asm_dec_reg)}
                        jmp decode_loop                   ; using jmp, loop auto decrements rcx

                    call_decoder:
                        call decoder
                        encoded_shellcode: db '{self.encoded_data}'
            """
        if self.variable_padding != 0:
            i = 0
            while i in range(0,self.variable_padding):
                nop = vi.nop_instruction()
                paddy = stub.split('\n')
                spacer = ' ' * 24
                noppy = f'{spacer}{nop}'
                random_noppy_index = random.randint(4, len(paddy)-4)
                paddy.insert(random_noppy_index, noppy)
                stub64_paddy = '\n'.join(paddy)
                cs.print(f'NOP inserted at line {random_noppy_index}: {nop}', cs.state_note)
                i += 1
            return stub64_paddy
        else:
            return stub
    
    def load_shellcode(self):
        if self.relay_input:
            shellcode_bytes = self.input
        else:
            try:
                cs.print(f'Try to open file {self.input}', cs.state_note)
                with open(self.input, 'rb') as file:
                    shellcode_bytes = file.read()
                    cs.action_open_file2(self.input)
            except FileNotFoundError:
                cs.print(f'File {self.input} not found or cannot be opened.', cs.state_fail)
                exit()
        self.shellcode = shellcode_bytes

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        fn_root, fn_extension = os.path.splitext(self.output)
        fn_obj = f'{fn_root}.obj'
        fn_asm = f'{fn_root}.nasm'
        self.load_shellcode()
        if self.decode:
            format_sc = self.shellcode.decode()
            sc = self.from_alphanum(format_sc)
        else:
            format_sc = ''.join(f'\\x{byte:02x}' for byte in self.shellcode)
            sc = self.to_alphanum(format_sc)
        self.encoded_data = sc
        if self.compile and self.CheckNasm():
            sc = self.gen_x64_stub()
            with open(fn_asm, 'wb') as f:
                if isinstance(sc, str):
                    f.write(sc.encode('utf-8'))
                else:
                    f.write(sc)
            run([self.compiler_cmd, '-f', 'win64', fn_asm, '-o', fn_obj])
            sc = get_coff_section(fn_obj, '.text')
        else:
            cs.print(f'nasm.exe not found! Download and place it into the shencode directory: {f_link}https://nasm.us/{f_end}', cs.state_fail)
        if self.relay_output:
            return sc
        else:
            cs.print(f'Writing to file {self.output}', cs.state_note)
            with open(self.output, 'wb') as f:
                if isinstance(sc, str):
                    f.write(sc.encode('utf-8'))
                else:
                    f.write(sc)
            cs.action_save_file2(self.output)
        cs.print('Done!', cs.state_ok)
