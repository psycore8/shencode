########################################################
### Info Module
### Status: migrated 085
###
########################################################

from keystone import *
from capstone import *
#from utils.helper import nstate as nstate
from utils.style import *
from utils.asm import variable_instruction_set
from utils.hashes import FunctionHash
from utils.const import *
import importlib

CATEGORY    = 'core'
DESCRIPTION = 'Developer Info Module'

arglist = {
    'get':                  { 'value': False, 'desc': 'Get developer info' },
    'modlist':              { 'value': False, 'desc': 'List modules' },
    'function_hash':        { 'value': '', 'desc': 'Returns Hash' },
    'prep_str':             { 'value': None, 'desc': 'Prepare a string for the stack' },
    'interactive':          { 'value': False, 'desc': 'Interactive mode (experimental), internal use only, do not change this value !!!' }
}

def register_arguments(parser):
    parser.add_argument('-g', '--get', action='store_true', help=arglist['get']['desc'])
    parser.add_argument('-m', '--modlist', action='store_true', help=arglist['modlist']['desc'])
    parser.add_argument('-fh', '--function-hash', help=arglist['function_hash']['desc'])

    opt = parser.add_argument_group('additional')
    opt.add_argument('--interactive', action='store_true', help=arglist['interactive']['desc'])
    opt.add_argument('--prep-str', help=arglist['prep_str']['desc'])

class module:
    import utils.header as header
    from os import listdir, path
    Author = 'psycore8'
    Version = '0.1.3'
    DisplayName = 'SHENCODE-DEViNFO'
    mod_dir = module_dir
    mod_count = 0
    mod_name = ''
    data_size = int
    hash = ''
    s = 40
    shell_path = '::core::info'

    def __init__(self, get, modlist=False, function_hash='', prep_str=any, interactive=bool):
        self.get = get
        self.modlist = modlist
        self.function_hash = function_hash
        self.prep_str = prep_str
        self.interactive = interactive    

    def msg(self, message_type, MsgVar=None, left_msg=None, right_msg=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'banner'         : f'{s_ok} Banners:'.ljust(self.s) + f'{len(self.header.headers)}',
            'version'        : f'{s_ok} Version:'.ljust(self.s) + f'{Version}',
            'mods'           : f'{s_ok} Modules:'.ljust(self.s) + f'{self.mod_count}',
            'repo'           : f'{s_ok} Repository:'.ljust(self.s) + f'{f_link}https://github.com/psycore8/shencode{f_end}',
            'docs'           : f'{s_ok} Docs:'.ljust(self.s) + f'{f_link}https://www.heckhausen.it/shencode/wiki{f_end}',
            'msf'            : f'{s_ok} msfvenom:'.ljust(self.s) + f' {msfvenom_path}',
            'template'       : f'{s_ok} template dir:'.ljust(self.s) + f'{tpl_path}',
            'modules'        : f'{s_ok} module dir:'.ljust(self.s) + f'{module_dir}',
            'out'            : f'{s_ok} {MsgVar}',
            'fout'           : f'{s_ok} {left_msg}'.ljust(self.s) + f'{right_msg}',
            'modlist.s'      : f'{s_ok} List modules',
            'modlist'        : f'{s_note} Module {self.mod_count}:{self.mod_name.upper()}',
            'post.done'      : f'{s_ok} DONE!'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def get_mod_count(self):
        self.mod_count = len([f for f in self.listdir(self.mod_dir) if self.path.isfile(self.path.join(self.mod_dir, f))])

    def get_modlist(self):
        for file in self.listdir(self.mod_dir):
            if file.endswith(".py") and not file.startswith("__"):
                mod_name = file[:-3] 
                return mod_name
            
    def interactive_module(self, module):
        mod = importlib.import_module(f'{module_dir}.{module}')
        shell_path = f'shencode{mod.module.shell_path}$ '
        #c = input(f'{BOLD}{clGRAY}shencode::core::info${ENDC} ')
        c = input(shell_path)
        if c == 'options':
            for arg in mod.module.arglist:
                print(f'{arg}: {mod.module.arglist.get(arg)}')
        elif c == 'exit':
            exit()
        self.interactive_module(module)
            
    def interactive_mode(self):
        #self.msg('Interactive Mode')
        asm_mode = 'asm'
        c = input(f'{BOLD}{clGRAY}shencode::core::info${ENDC} ')
        cmd = c.split(' ')
        if c == 'exit':
            exit()
        elif cmd[0] == 'set':
            asm_mode = cmd[1]
            print(f'ASM mode set to: {asm_mode}')
        elif cmd[0] == 'load':
            mod_loader = cmd[1]
            self.interactive_module(mod_loader)
        else:
            if asm_mode == 'asm':
                try:
                    ks = Ks(KS_ARCH_X86, KS_MODE_64)
                    code, count = ks.asm(c)
                    print("".join("\\x{:02x}".format(b) for b in code))
                except KsError as e:
                    print("ERROR: %s" %e)
            elif asm_mode == 'dism':
                try:
                    c = b'\x55\x48\x8b\x05\xb8\x13\x00\x00'
                    cs = Cs(CS_ARCH_X86, CS_MODE_64)
                    for i in cs.disasm(c, 0x1000):
                        print("0x{0:x}:\t{1}\t{2}".format(i.address, i.mnemonic, i.op_str))
                except CsError as e:
                    print('ERROR: %s' %e)
        self.interactive_mode()

    def process(self):
        vi = variable_instruction_set()
        m = self.msg
        self.msg('pre.head')
        self.msg('version')
        self.msg('banner')
        if self.interactive:
            print('Input Assembler instructions or type "exit"')
            self.interactive_mode()
        if self.function_hash != None:
            print(f"[DEBUG] Eingabewert: {self.function_hash}")
            fh = FunctionHash()
            hash_r = fh.ror_hash(self.function_hash, 13)
            print(f'[ROR13] {self.function_hash} : {hex(hash_r)}')
            exit()
        if self.prep_str != None:
            stack_list = vi.prepare_str_to_stack(self.prep_str)
            for stack_string in stack_list:
                print(stack_string)
            exit()
        self.get_mod_count()
        self.msg('mods')
        self.msg('modules')
        m('fout', None, 'nasm:', f'{nasm}')
        m('fout', None, 'Resource dir:', f'{resource_dir}')
        self.msg('template')
        self.msg('msf')
        self.msg('repo')
        self.msg('docs')
        if self.modlist:
            self.mod_count = 1
            for file in self.listdir(self.mod_dir):
                if file.endswith(".py") and not file.startswith("__"):
                    if self.mod_count >= 10:
                        spacer = ' '*7
                    else:
                        spacer = ' '*8
                    self.mod_name = spacer + file[:-3]
                    self.msg('modlist')
                    self.mod_count += 1
        self.msg('post.done')
                
