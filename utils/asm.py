###
### Variable instruction sets
###

from utils.const import *

class variable_instruction_set:
    import random

    def __init__(self, whitespaces=0):
        self = self
        self.whitespaces = whitespaces

    register_set_zero = ['xor', 'sub']
    test_condition = ['test', 'or']
    jump_conditional_positive = ['jz', 'je']  
    jump_conditional_negative = ['jnz', 'jne']
    multi_bit_registers = [
        ['rax', 'eax', 'ax', 'al'],
        ['rbx', 'ebx', 'bx', 'bl'],
        ['rcx', 'ecx', 'cx', 'cl'],
        ['rdx', 'edx', 'dx', 'dl'],
        ['r9', 'r9d', 'r9w', 'r9b'],
        ['r8', 'r8d', 'r8w', 'r8b'],
        ['rsi', 'esi', 'si', 'sil'],
        ['rdi', 'edi', 'di', 'dil'],
        ['r10', 'r10d', 'r10w', 'r10b'],
        ['r11', 'r11d', 'r11w', 'r11b']
    ]
    hash_algorithm = [ 'rol', 'ror']

    def zero_register(self, register_name):
        ws = ' ' * self.whitespaces
        instruction_set = [
            f'xor {register_name}, {register_name}',
            f'sub {register_name}, {register_name}',
            f'mov {register_name}, 0xFFFFFFFFFFFFFFFF\n{ws}add {register_name}, 1'
        ]
        return self.random.choice(instruction_set)

    def increase_register(self, register_name, value=1):
        instruction_set = [
            f'inc {register_name}',
            f'add {register_name}, {value}',
            f'lea {register_name}, [{register_name} + {value}]'
            ]
        return self.random.choice(instruction_set)
    
    def decrease_register(self, register_name, value=1):
        instruction_set = [
            f'dec {register_name}',
            f'sub {register_name}, {value}',
            f'lea {register_name}, [{register_name} - {value}]'
            ]
        return self.random.choice(instruction_set)
    
    def jump_instruction(self, jump_target):
        ws = ' ' * self.whitespaces
        instruction_set = [
            f'jmp {jump_target}',
            f'call {jump_target}'
            #f'mov {jump_register}, {jump_target}\n{ws}push {jump_register}\n{ws}ret'
        ]
        return self.random.choice(instruction_set)
    
    def nop_instruction(self):
        instruction_set = [
            'xchg eax, eax',
            'xchg esi, esi',
            'xchg edi, edi',
            'lea eax, [eax]',
            'lea esi, [esi]',
            'lea edx, [edx]',
            'mov edi, edi',
            'mov ebx, ebx',
            'nop',
            #'66 nop',
            'rex nop'
            #'nop dword ptr [ecx]',
            #'nop dword ptr [eax+eax*1+01]'
        ]
        return self.random.choice(instruction_set)
    
    def generate_jump_label(self):
        diceware_dict = {}
        with open(f'{resource_dir}wordlist_en_eff.txt', 'r') as file:
            for line in file:
                key, value = line.strip().split(maxsplit=1)
                diceware_dict[key] = value
        dice_roll = ''.join(str(self.random.randint(1, 6)) for _ in range(5))
        word = diceware_dict.get(dice_roll, 'Nothing found')
        return word
  
    def prepare_str_to_stack(self, string_to_convert, register_name):
        hasPadding = False
        str_list = []
        b = string_to_convert.encode('utf-8')

        orig_len = len(b)
        padd_len = (8 - orig_len % 8) % 8

        if padd_len:
            b += b'\x11' * padd_len
            hasPadding = True
        chunks = [b[i:i+8] for i in range(0, len(b), 8)]

        for chunk in reversed(chunks):
            word = int.from_bytes(chunk, byteorder='little')
            if hasPadding:
                pbits = padd_len * 8
                str_list += [
                    f'mov {register_name}, 0x{word:08x}            ; {chunk.decode()}', 
                    f'shl {register_name}, {pbits}', 
                    f'shr {register_name}, {pbits}',
                    f'push {register_name}'
                    ]
                hasPadding = False
            else:
                str_list += [
                    f'mov {register_name}, 0x{word:08x}            ; {chunk.decode()}',
                    f'push {register_name}'
                    ]
        return str_list