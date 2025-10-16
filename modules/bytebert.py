### DEFINITIONS
# reg1 = save / read encryptedbyte(odd)
# reg2 = shellcode indexer
# reg3 = counter
# reg1, reg2 = random.sample(registers, 2)

import random
from utils.asm import variable_instruction_set
from utils.style import *
from utils.helper import CheckFile
from utils.binary import get_coff_section
from os import path as osp
from os import name as os_name
from os import urandom as urandom
from subprocess import run
from tqdm import tqdm
from utils.const import *

CATEGORY    = 'encoder'
DESCRIPTION = 'ByteBert - Advanced polymorphic Encoder Stub'

cs = ConsoleStyles()

arglist = {
    'input':                    { 'value': None, 'desc': 'Input file to use with bytebert' },
    'output':                   { 'value': None, 'desc': 'Outputfile for bytebert' },
    'variable_padding':         { 'value': False, 'desc': 'Inserts random NOPs to differ the padding' },
    'verbose':                  { 'value': False, 'desc': 'Verbose mode' }
}

def register_arguments(parser):
            parser.add_argument('-i', '--input', help=arglist['input']['desc'])
            parser.add_argument('-o', '--output', help=arglist['output']['desc'])
            parser.add_argument('-v', '--variable-padding', type=int, help=arglist['variable_padding']['desc'])
            add = parser.add_argument_group('Additional')
            add.add_argument('--verbose', action='store_true', help=arglist['verbose']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'ByteBERT-ENC'
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
    shell_path = '::encoder::ByteBert'

    def __init__(self, input, output, variable_padding=0, verbose=bool):
        self.input = input
        self.output = output
        if variable_padding == None:
            variable_padding = 0
        self.variable_padding = variable_padding
        self.verbose = verbose
        self.compiler_cmd = nasm

    def CheckNasm(self)->bool:
        if osp.exists(self.compiler_cmd):
            return True
        else:
            return False
        
    def encrypt(self, data: bytes, xor_key: int) -> bytes:
        transformed = bytearray()
        prev_enc_byte = 0
        for i, byte in enumerate(data):
            if i % 2 == 0: # even byte positions
                enc_byte = byte ^ xor_key
            else:          # odd byte positions
                enc_byte = byte ^ prev_enc_byte
            
            transformed.append(enc_byte)
            prev_enc_byte = enc_byte

        return bytes(transformed)

    def LoadHeader(self):
        self.Modified_Shellcode = self.generate_win64_stub()
        self.stub_size = len(self.Modified_Shellcode)
        #cs.print(f'ASM script generated with a size of {self.stub_size} bytes', cs.state_note)
        cs.console_print.note(f'ASM script generated with a size of {self.stub_size} bytes')

    def LoadShellcode(self):
        self.key = random.randint(1, 255)
        if self.relay_input:
            shellcode_bytes = self.input
        else:
            try:
                with open(self.input, 'rb') as file:
                    shellcode_bytes = file.read()
            except FileNotFoundError:
                cs.console_print.error('File not found')
        cs.console_print.info(f'Random key: {self.key} ({hex(self.key)})')

        for i in tqdm (range (100), colour='magenta', leave=False):
            self.Shellcode_Bin = self.encrypt(shellcode_bytes, self.key)
        size = len(self.Shellcode_Bin)
        self.Shellcode_Length = str(size)
        self.end_offset = str( 404 )
        cs.console_print.note(f'Payload size: {self.Shellcode_Length}')

    def ConvertShellCodeToStr(self):
        self.Shellcode = [f"0x{byte:02X}" for byte in self.Shellcode_Bin]
        self.Shellcode = '      Shellcode: db '+','.join(self.Shellcode)

    def AppendShellcode(self):
        self.Modified_Shellcode += self.Shellcode
        cs.console_print.ok('Encoded payload appended!')

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
        cs.module_header(self.DisplayName, self.Version)
        fn_Root, output_file_extension = osp.splitext(self.output)
        fn_nasm = f'{fn_Root}.nasm'
        fn_obj = f'{fn_Root}.obj'

        if not self.relay_input and CheckFile(self.input):
            self.LoadShellcode()
            cs.action_open_file2(self.input)
        elif self.relay_input:
            self.LoadShellcode()
        else:
            cs.console_print.error(f'File {self.input} not found or cannot be opened')
        self.LoadHeader()
        self.ConvertShellCodeToStr()
        self.AppendShellcode()
        self.WriteToFile(self.Modified_Shellcode, fn_nasm)
        if self.verbose: cs.action_save_file2(fn_nasm)
        if self.CheckNasm():
            cs.console_print.note('Try to compile object file')
            self.CompileObjectFile(fn_nasm, fn_obj)
            if CheckFile(fn_obj):
                if self.verbose: cs.action_save_file2(fn_obj)
                cs.console_print.info('Extract .text section from object file')
                final_shellcode = get_coff_section(fn_obj, '.text')
                shellcode_size = str(len(final_shellcode))
                cs.console_print.info(f'Final shellcode size: {shellcode_size} bytes')
                if self.relay_output:
                    cs.console_print.ok('DONE!')
                    return final_shellcode
                else:
                    self.WriteToFile(final_shellcode, self.output)
                    cs.action_save_file2(self.output)
                    cs.console_print.ok('DONE!')
        else:
            cs.console_print.error(f'nasm.exe not found! Download and place it into the shencode directory: [cyan underline]https://nasm.us/[/]')
            cs.console_print.info(f'You can compile it by hand: nasm.exe -f win64 {fn_nasm} -o {fn_obj}')

    def generate_win64_stub(self):
        vi = variable_instruction_set()
        reg1, reg2, reg3, reg4 = random.sample(vi.multi_bit_registers, 4)

        inst_asm_reg_zero = ['xor', 'sub']
        inst_asm_jmp_cond = ['jz', 'je']
        inst_asm_jmp_ncond = ['jnz', 'jne']
        inst_asm_inc_reg = [
            f'inc {reg4[0]}',
            f'add {reg4[0]}, 1',
            f'lea {reg4[0]}, [{reg4[0]}+1]'
            ]
        inst_asm_dec_reg = [
            f'dec {reg3[0]}',
            f'sub {reg3[0]}, 1',
            f'lea {reg3[0]}, [{reg3[0]}-1]'
            ]
        
        rc = random.choice
        asm_reg_zero    = random.choice(inst_asm_reg_zero)
        asm_jmp_cond    = random.choice(inst_asm_jmp_cond)
        asm_jmp_ncond   = random.choice(inst_asm_jmp_ncond)
        asm_inc_reg     = random.choice(inst_asm_inc_reg)
        asm_dec_reg     = random.choice(inst_asm_dec_reg)

        if self.verbose:
            cs.console_print.info(f'Selected registers: {reg1[0]}, {reg2[0]}, {reg3[0]}, {reg4[0]}')
            cs.console_print.info(f'Instruction set: {asm_jmp_cond} / {asm_jmp_ncond} / {asm_reg_zero}')
            cs.console_print.info(f'Increase, decrease: {asm_inc_reg} {asm_dec_reg}')

        size = int(self.Shellcode_Length)
        
        if size <= 255:
           sc_size = f'mov {reg3[3]}, {size}'
        elif size <= 65535:
           sc_size = f'mov {reg3[2]}, {size}'
        else:
           sc_size = f'mov {reg3[1]}, {size}'

        if self.verbose:
           cs.console_print.info(f'Size instruction: {sc_size}')
        
        stub64 = f"""
            section .data

            section .text
                global _start

                    _start:
                        {rc(inst_asm_reg_zero)} {reg1[0]}, {reg1[0]}
                        {rc(inst_asm_reg_zero)} {reg2[0]}, {reg2[0]}
                        {rc(inst_asm_reg_zero)} {reg3[0]}, {reg3[0]}
                        {rc(inst_asm_reg_zero)} {reg4[0]}, {reg4[0]}
                        {sc_size}              ; length of embedded shellcode
                        jmp short call_decoder   ; JMP-CALL-POP: 1. JMP

                    decoder:
                        pop {reg4[0]}                  ; JMP-CALL-POP: 3. POP

                    decode_loop:
                        test {reg3[0]}, {reg3[0]}            ; are we ready?
                        {asm_jmp_cond} Shellcode             ; jump, if finished

                        ; even byte (Index % 2 == 0)
                        mov {reg2[0]}, {reg4[0]}
                        sub {reg2[3]}, Shellcode        ; calculate Index (rsi - Shellcode)
                        test {reg2[3]}, 1               ; check: Index & 1 (odd or even?)
                        {asm_jmp_ncond} odd_byte             ; jump, if odd

                        ; processing for even bytes
                        mov {reg1[3]}, [{reg4[0]}]			 ; save actual encrypted byte for the next loop
                        xor byte [{reg4[0]}], {self.key}     ; decrypt byte in shellcode: byte sub negate(key)
                        jmp post_processing

                    odd_byte:
                        ; processing for odd bytes
                        ; not {reg1[3]}
                        xor byte [{reg4[0]}], {reg1[3]}        ; decrypt: encoded_byte sub negate(previous_encoded_byte)

                    post_processing:
                        {asm_inc_reg}                  ; next encrypted byte
                        {asm_dec_reg}                  ; decrease length
                        jmp decode_loop          ; back to the loop

                    call_decoder:
                        call decoder             ; JMP-CALL-POP: 2. CALL
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
                    cs.console_print.info(f'Added NOP at line {random_noppy_index}')
                i += 1
            return stub64_paddy
        else:
            return stub64