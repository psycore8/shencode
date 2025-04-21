import os

module_dir = 'modules'
Version = '0.8.2'
banner = 13

if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  nasm = 'nasm.exe'
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  nasm = 'nasm'
  tpl_path = 'tpl/'

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

hash_algorythm = [
  'rol', 'ror'
]

class variable_instruction_set:
  import random

  def __init__(self):
    self = self

  register_set_zero = ['xor', 'sub']
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
  hash_algorythm = [ 'rol', 'ror']

  def increase_register(self, register_name):
    instruction_set = [
        f'inc {register_name}',
        f'add {register_name}, 1',
        f'lea {register_name}, [{register_name}+1]'
        ]
    return self.random.choice(instruction_set)
  
  def decrease_register(self, register_name):
    instruction_set = [
        f'dec {register_name}',
        f'sub {register_name}, 1',
        f'lea {register_name}, [{register_name}-1]'
        ]
    return self.random.choice(instruction_set)