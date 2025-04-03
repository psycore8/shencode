import os

module_dir = 'modules'
Version = '0.8.1'
banner = -1

if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
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
