########################################################
### ByteBert Module
### Status: cleaned, 083
### 
########################################################

### DEFINITIONS
# reg1 = save / read encryptedbyte(odd)
# reg2 = shellcode indexer
# reg3 = counter
# reg1, reg2 = random.sample(registers, 2)

import random
from utils.asm import variable_instruction_set
from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from utils.binary import get_coff_section
from os import path as osp
from os import name as os_name
from os import urandom as urandom
from subprocess import run
#import struct
from tqdm import tqdm
from utils.const import *

CATEGORY    = 'encoder'
DESCRIPTION = 'ByteBert - Advanced polymorphic Encoder Stub'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file to use with bytebert')
            parser.add_argument('-o', '--output', help='outputfile for bytebert')
            parser.add_argument('-v', '--variable-padding', action='store_true', help='Inserts a random NOP to differ the padding')
            add = parser.add_argument_group('Additional')
            add.add_argument('--verbose', action='store_true', help='Verbose mode')

class module:
    Author = 'psycore8'
    Version = '0.4.1'
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

    def __init__(self, input, output, variable_padding=bool, verbose=bool):
        self.input = input
        self.output = output
        self.variable_padding = variable_padding
        self.verbose = verbose
        self.compiler_cmd = nasm

    def msg(self, message_type, ErrorExit=False, MsgVar=any):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'proc.ssize'    : f'{nstate.s_note} ASM script generated with a size of {self.stub_size} bytes',
            'proc.rkey'     : f'{nstate.s_note} Random key: {self.key} ({hex(self.key)})',
            'error.input'   : f'{nstate.s_fail} File {self.input} not found or cannot be opened.',
            'error.output'  : f'{nstate.s_fail} File {MsgVar} not found or cannot be opened.',
            'proc.psize'    : f'{nstate.s_note} Payload size: {self.Shellcode_Length}',
            'proc.xor_ok'   : f'{nstate.s_ok} Encoded payload appended!',
            'proc.out'      : f'{nstate.s_ok} File created in {MsgVar}\n{nstate.s_note} Hash: {self.hash}',
            'proc.comp_try' : f'{nstate.s_note} Try to compile object file',
            'proc.input_ok' : f'{nstate.s_ok} File {self.input} loaded\n{nstate.s_note} Size of shellcode {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.compile'  : f'{nstate.s_ok} File {MsgVar} created\n{nstate.s_note} Size of shellcode {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.ext'      : f'{nstate.s_info} Extract .text section from object file',
            'proc.fsize'    : f'{nstate.s_info} Final shellcode size: {MsgVar} bytes',
            'error.xor_ok'  : f"{nstate.s_fail} XOR encoded Shellcode error, aborting script execution",
            'error.nasm1'   : f'{nstate.s_fail} nasm.exe not found! Download and place it into the shencode directory: {nstate.f_link}https://nasm.us/{nstate.f_end}',
            'key.try'       : f'{nstate.s_info} Bruteforcing XOR key',
            'error.key'     : f'{nstate.s_fail} \\x00 detected! Proceeding with random key',
            'error.nasm2'   : f'{nstate.s_info} You can compile it by hand: nasm.exe -f win64 {MsgVar}',
            # Verbose
            'v.registers'   : f'{nstate.s_info} Selected registers: {MsgVar}',
            'v.inst'        : f'{nstate.s_info} {MsgVar}',
            'v.size'        : f'{nstate.s_info} Size instruction: {MsgVar}',
            'v.padding'     : f'{nstate.s_info} Added NOP at line {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def CheckNasm(self)->bool:
        if osp.exists(self.compiler_cmd):
            return True
        else:
            return False
        
    # def find_valid_xor_key(self, shellcode):
    #     for key in range(1, 255):
    #         #print(key)
    #         if all((b ^ key) != 0 for b in shellcode): 
    #             return key
    #     return 0 
    
    # def find_valid_xor_key2(self, shellcode):
    #     #widgets = ['Loading: ', progressbar.AnimatedMarker()]
    #     #bar = progressbar.ProgressBar(widgets=widgets).start()        
    #     #for i in tqdm (range (255), colour='magenta', leave=True):
    #     # with tqdm(desc="Processing: ", dynamic_ncols=True) as pbar:
    #     #     while True:
    #     #         key = urandom(1)[0]  # Zufälliges Byte als Schlüssel
    #     #         pbar.update(1)
    #     #         #print(f'Checking {key}')
    #     #         if all((b ^ key) != 0 for b in shellcode):  # Prüfen, ob XOR keine Null-Bytes erzeugt
    #     #             return key
    #     for i in range(255):
    #         print(i)
    #         self.encrypt(i)

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
        self.msg('proc.ssize')

    def LoadShellcode(self):
        self.key = random.randint(1, 255)
        if self.relay_input:
            shellcode_bytes = self.input
        else:
            try:
                with open(self.input, 'rb') as file:
                    shellcode_bytes = file.read()
            except FileNotFoundError:
                self.msg('error.input', True)
        self.msg('proc.rkey')

        for i in tqdm (range (100), colour='magenta', leave=False):
            self.Shellcode_Bin = self.encrypt(shellcode_bytes, self.key)
        size = len(self.Shellcode_Bin)
        self.Shellcode_Length = str(size)
        self.end_offset = str( 404 )
        self.msg('proc.psize')

    def ConvertShellCodeToStr(self):
        self.Shellcode = [f"0x{byte:02X}" for byte in self.Shellcode_Bin]
        self.Shellcode = '      Shellcode: db '+','.join(self.Shellcode)

    def AppendShellcode(self):
        self.Modified_Shellcode += self.Shellcode
        self.msg('proc.xor_ok')

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

        fn_Root, output_file_extension = osp.splitext(self.output)
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
            self.msg('proc.out', False, f'{fn_nasm}')
        else:
            self.msg('error.output', True, f'{fn_nasm}')
        if self.CheckNasm():
            self.msg('proc.comp_try')
            self.CompileObjectFile(fn_nasm, fn_obj)
            if CheckFile(fn_obj):
                self.data_size, self.hash = GetFileInfo(fn_obj)
                self.msg('proc.compile', False, f'{fn_obj}')
                self.msg('proc.ext')
                final_shellcode = get_coff_section(fn_obj, '.text')
                self.msg('proc.fsize', False, len(final_shellcode))
                if self.relay_output:
                    self.msg('post.done')
                    return final_shellcode
                else:
                    self.WriteToFile(final_shellcode, self.output)
                    self.msg('post.done')
        else:
            self.msg('error.nasm1')
            self.msg('error.nasm2', True, f'{fn_nasm} -o {fn_obj}')

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
            self.msg('v.registers', False, f'{reg1[0]}, {reg2[0]}, {reg3[0]}, {reg4[0]}')
            self.msg('v.inst', False, f'Instruction set: {asm_jmp_cond} / {asm_jmp_ncond} / {asm_reg_zero}')
            self.msg('v.inst', False, f'Increase, decrease: {asm_inc_reg} {asm_dec_reg}')

        size = int(self.Shellcode_Length)
        
        if size <= 255:
           sc_size = f'mov {reg3[3]}, {size}'
        elif size <= 65535:
           sc_size = f'mov {reg3[2]}, {size}'
        else:
           sc_size = f'mov {reg3[1]}, {size}'

        if self.verbose:
            self.msg('v.size', False, f'{sc_size}')
        
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
        
        if self.variable_padding:
            nop = vi.nop_instruction()
            paddy = stub64.split('\n')
            spacer = ' ' * 24
            noppy = f'{spacer}{nop}'
            random_noppy_index = random.randint(6, len(paddy)-2)
            paddy.insert(random_noppy_index, noppy)
            stub64_paddy = '\n'.join(paddy)
            if self.verbose:
                self.msg('v.padding', False, f'{random_noppy_index}')
            return stub64_paddy
        else:
            return stub64