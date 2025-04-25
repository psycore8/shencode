import os

module_dir = 'modules'
Version = '0.8.3'
banner = -1

if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  nasm = 'nasm.exe'
  resource_dir = 'resources\\'
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  nasm = 'nasm'
  resource_dir = 'resources/'
  tpl_path = 'tpl/'

# multi_bit_registers = [
#     ['rax', 'eax', 'ax', 'al'],
#     ['rbx', 'ebx', 'bx', 'bl'],
#     ['rcx', 'ecx', 'cx', 'cl'],
#     ['rdx', 'edx', 'dx', 'dl'],
#     ['r9', 'r9d', 'r9w', 'r9b'],
#     ['r8', 'r8d', 'r8w', 'r8b'],
#     ['rsi', 'esi', 'si', 'sil'],
#     ['rdi', 'edi', 'di', 'dil'],
#     ['r10', 'r10d', 'r10w', 'r10b'],
#     ['r11', 'r11d', 'r11w', 'r11b']
# ]

# hash_algorithm = [
#   'rol', 'ror'
# ]

# class variable_instruction_set:
#   import random

#   def __init__(self):
#     self = self

#   register_set_zero = ['xor', 'sub']
#   jump_conditional_positive = ['jz', 'je']  
#   jump_conditional_negative = ['jnz', 'jne']
#   multi_bit_registers = [
#     ['rax', 'eax', 'ax', 'al'],
#     ['rbx', 'ebx', 'bx', 'bl'],
#     ['rcx', 'ecx', 'cx', 'cl'],
#     ['rdx', 'edx', 'dx', 'dl'],
#     ['r9', 'r9d', 'r9w', 'r9b'],
#     ['r8', 'r8d', 'r8w', 'r8b'],
#     ['rsi', 'esi', 'si', 'sil'],
#     ['rdi', 'edi', 'di', 'dil'],
#     ['r10', 'r10d', 'r10w', 'r10b'],
#     ['r11', 'r11d', 'r11w', 'r11b']
#   ]
#   hash_algorithm = [ 'rol', 'ror']

#   def increase_register(self, register_name, value=1):
#     instruction_set = [
#         f'inc {register_name}',
#         f'add {register_name}, {value}',
#         f'lea {register_name}, [{register_name} + {value}]'
#         ]
#     return self.random.choice(instruction_set)
  
#   def decrease_register(self, register_name, value=1):
#     instruction_set = [
#         f'dec {register_name}',
#         f'sub {register_name}, {value}',
#         f'lea {register_name}, [{register_name} - {value}]'
#         ]
#     return self.random.choice(instruction_set)
  
#   def generate_jump_label(self):
#       diceware_dict = {}
#       with open(f'{resource_dir}wordlist_en_eff.txt', 'r') as file:
#           for line in file:
#               key, value = line.strip().split(maxsplit=1)
#               diceware_dict[key] = value
#       dice_roll = ''.join(str(self.random.randint(1, 6)) for _ in range(5))
#       word = diceware_dict.get(dice_roll, 'Nothing found')
#       return word