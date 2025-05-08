########################################################
### Alphanum Module
### Status: migrated to 082
### 
########################################################

import os
import random
import tqdm
from utils.asm import variable_instruction_set
from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from utils.const import *
from utils.binary import get_coff_section
from subprocess import run

CATEGORY    = 'encoder'
DESCRIPTION = 'Encode bytes to alphanumeric output'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file to use')
            parser.add_argument('-o', '--output', help='Output file to use')

            add = parser.add_argument_group('Additional')
            add.add_argument('-c', '--compile', default=False, action='store_true' ,help='Compile object file and extract shellcode')
            add.add_argument('-d', '--decode', default=False, action='store_true' ,help='Decode the input to bytes')

class module:
    Author          = 'psycore8'
    Version         = '0.1.6'
    DisplayName     = 'AlphaNum'
    shellcode       = b''
    encoded_data    = ''
    relay_input     = False
    relay_output    = False

    def __init__(self, input, output, decode=False, compile=False):
            self.input = input
            self.output = output
            self.decode = decode
            self.compile = compile
            self.compiler_cmd = nasm

    def msg(self, message_type, ErrorExit=False, MsgVar=str):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'proc.input_ok'  : f'{nstate.s_ok} {MsgVar}',
            'proc.output_ok' : f'{nstate.s_ok} {MsgVar}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input}',
            'proc.output_try': f'{nstate.s_note} Writing to file {self.output}',
            'error.input'    : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output} not found or cannot be opened.',
            'note'           : f'{nstate.s_note} {MsgVar}',
            'ok'             : f'{nstate.s_ok} {MsgVar}',
            'post.done'      : f'{nstate.s_ok} DONE!'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def to_alphanum(self, encoded_shellcode):
        self.msg('note', False, 'Encoder running...')
        alphanum_shellcode = ''
        for hex_byte in tqdm.tqdm (encoded_shellcode.split('\\x')[1:], colour='magenta'):
            num = int(hex_byte, 16)
            high = (num >> 4) + 0x41  # A-Z (65-90)
            low = (num & 0xF) + 0x61  # a-p (97-112)
            alphanum_shellcode += chr(high) + chr(low)
        return alphanum_shellcode
    
    def from_alphanum(self, alphanum_shellcode):
        self.msg('note', False, 'Decoder running...')
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
                        ;loop decode_loop                 ; repeat until it is done

                        ;jmp {reg1[0]}                    ; jump to shellcode

                    call_decoder:
                        call decoder
                        encoded_shellcode: db '{self.encoded_data}'
            """
        return stub
    
    def load_shellcode(self):
        if self.relay_input:
            shellcode_bytes = self.input
        else:
            try:
                self.msg('proc.input_try')
                with open(self.input, 'rb') as file:
                    size, hash = GetFileInfo(self.input)
                    self.msg('proc.input_ok', False, f'File {self.input} loaded\n{nstate.s_ok} Size of shellcode {size} bytes\n{nstate.s_ok} Hash: {hash}')
                    shellcode_bytes = file.read()
            except FileNotFoundError:
                self.msg('error.input', True)
        self.shellcode = shellcode_bytes

    def process(self):
        m = self.msg
        m('pre.head')
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
        if self.compile:
            sc = self.gen_x64_stub()
            with open(fn_asm, 'wb') as f:
                if isinstance(sc, str):
                    f.write(sc.encode('utf-8'))
                else:
                    f.write(sc)
            run([self.compiler_cmd, '-f', 'win64', fn_asm, '-o', fn_obj])
            sc = get_coff_section(fn_obj, '.text')
        if self.relay_output:
            return sc
        else:
            m('proc.output_try')
            with open(self.output, 'wb') as f:
                if isinstance(sc, str):
                    f.write(sc.encode('utf-8'))
                else:
                    f.write(sc)
            if CheckFile(self.output):
                size, hash = GetFileInfo(self.output)
                m('proc.output_ok', False, f'File {self.output} created\n{nstate.s_ok} Size {size} bytes\n{nstate.s_ok} Hash: {hash}')
            else:
                m('error.output', True)

        m('post.done')  