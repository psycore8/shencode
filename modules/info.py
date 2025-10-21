########################################################
### ShenCode Module
###
### Name: Info Module
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from keystone import *
from capstone import *
from utils.style import *
from utils.asm import variable_instruction_set
from utils.hashes import FunctionHash
from utils.const import *

CATEGORY    = 'core'
DESCRIPTION = 'Developer Info Module'

cs = ConsoleStyles()
arglist = {
    'get':                  { 'value': False, 'desc': 'Get developer info' },
    'modlist':              { 'value': False, 'desc': 'List modules' },
    'function_hash':        { 'value': '', 'desc': 'Returns Hash' },
    'prep_str':             { 'value': None, 'desc': 'Prepare a string for the stack' },
}

def register_arguments(parser):
    parser.add_argument('-g', '--get', action='store_true', help=arglist['get']['desc'])
    parser.add_argument('-m', '--modlist', action='store_true', help=arglist['modlist']['desc'])
    parser.add_argument('-fh', '--function-hash', help=arglist['function_hash']['desc'])

    opt = parser.add_argument_group('additional')
    opt.add_argument('--prep-str', help=arglist['prep_str']['desc'])

class module:
    import utils.header as header
    from os import listdir, path
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'SHENCODE-DEViNFO'
    mod_dir = module_dir
    mod_count = 0
    mod_name = ''
    data_size = int
    hash = ''
    s = 40
    shell_path = '::core::info'

    def __init__(self, get, modlist=False, function_hash='', prep_str=any):
        self.get = get
        self.modlist = modlist
        self.function_hash = function_hash
        self.prep_str = prep_str 

    def get_mod_count(self):
        self.mod_count = len([f for f in self.listdir(self.mod_dir) if self.path.isfile(self.path.join(self.mod_dir, f))])

    def get_modlist(self):
        for file in self.listdir(self.mod_dir):
            if file.endswith(".py") and not file.startswith("__"):
                mod_name = file[:-3] 
                return mod_name
            
    def process(self):
        vi = variable_instruction_set()
        cs.module_header(self.DisplayName, self.Version)
        cs.console_print.ok(f'Version:'.ljust(self.s) + f'{Version}')
        cs.console_print.ok(f'Banners:'.ljust(self.s) + f'{len(self.header.headers)}')
        if self.function_hash != None:
            cs.console_print.ok(f"[DEBUG] Eingabewert: {self.function_hash}")
            fh = FunctionHash()
            hash_r = fh.ror_hash(self.function_hash, 13)
            cs.console_print.ok(f'[ROR13] {self.function_hash} : {hex(hash_r)}')
            exit()
        if self.prep_str != None:
            stack_list = vi.prepare_str_to_stack(self.prep_str)
            for stack_string in stack_list:
                cs.console_print.ok(stack_string)
            exit()
        self.get_mod_count()
        cs.console_print.note(f'Modules:'.ljust(self.s) + f'{self.mod_count}')
        cs.console_print.note(f'Module dir:'.ljust(self.s) + f'{module_dir}')
        cs.console_print.note(f'NASM:'.ljust(self.s) + f'{nasm}')
        cs.console_print.note(f'Resource dir:'.ljust(self.s) + f'{resource_dir}')
        cs.console_print.note(f'Template dir:'.ljust(self.s) + f'{tpl_path}')
        cs.console_print.note(f'Msfvenom:'.ljust(self.s) + f'{msfvenom_path}')
        cs.console_print.note(f'Repository:'.ljust(self.s) + f'[url]https://github.com/psycore8/shencode[/]')
        cs.console_print.note(f'Docs:'.ljust(self.s) + f'[url]https://www.heckhausen.it/shencode/wiki[/]')

        if self.modlist:
            self.mod_count = 1
            for file in self.listdir(self.mod_dir):
                if file.endswith(".py") and not file.startswith("__"):
                    if self.mod_count >= 10:
                        spacer = ' '*7
                    else:
                        spacer = ' '*8
                    self.mod_name = spacer + file[:-3]
                    cs.console_print.note(f'Module {self.mod_count}:{self.mod_name.upper()}')
                    self.mod_count += 1
        cs.console_print.ok('DONE!')
                
