########################################################
### Info Module
### Status: untested
########################################################

from utils.helper import nstate as nstate
from utils.asm import variable_instruction_set
from utils.hashes import FunctionHash
from utils.const import *

CATEGORY = 'core'

def register_arguments(parser):
    parser.add_argument('-g', '--get', action='store_true', help='Get developer info')
    parser.add_argument('-m', '--modlist', action='store_true', help='List modules')
    parser.add_argument('-fh', '--function-hash', help='Returns Hash')

    opt = parser.add_argument_group('additional')
    opt.add_argument('--prep-str', help='Prepare a string for the stack')

class module:
    import utils.header as header
    from os import listdir, path
    Author = 'psycore8'
    Description = 'Info'
    Version = '0.0.5'
    DisplayName = 'SHENCODE-DEViNFO'
    mod_dir = module_dir
    mod_count = 0
    mod_name = ''
    data_size = int
    hash = ''

    def __init__(self, get, modlist=False, function_hash='', prep_str=any):
        self.get = get
        self.modlist = modlist
        self.function_hash = function_hash
        self.prep_str = prep_str
        

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'banner'         : f'{nstate.s_ok} Banner count: {len(self.header.headers)}',
            'version'        : f'{nstate.s_ok} ShenCode Version: {Version}',
            'mods'           : f'{nstate.s_ok} Module count: {self.mod_count}',
            'repo'           : f'{nstate.s_ok} Repository: {nstate.f_link}https://github.com/psycore8/shencode{nstate.f_end}',
            'docs'           : f'{nstate.s_ok} Docs: {nstate.f_link}https://www.heckhausen.it/shencode/wiki{nstate.f_end}',
            'msf'            : f'{nstate.s_ok} msfvenom: {msfvenom_path}',
            'template'       : f'{nstate.s_ok} template dir: {tpl_path}',
            'modules'        : f'{nstate.s_ok} module dir: {module_dir}',
            'modlist.s'      : f'{nstate.s_ok} List modules',
            'modlist'        : f'{nstate.s_note} Module {self.mod_count}:{self.mod_name.upper()}',
            'post.done'      : f'{nstate.s_ok} DONE!'
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

    def process(self):
        vi = variable_instruction_set()
        self.msg('pre.head')
        self.msg('version')
        self.msg('banner')
        #print(self.function_hash)
        if self.function_hash != None:
            #value_to_hash = self.function_hash.lower().encode('ascii') + b'\x00'
            print(f"[DEBUG] Eingabewert: {self.function_hash}")
            #print(self.function_hash.encode().hex())
            fh = FunctionHash()
            hash_r = fh.ror_hash(self.function_hash, 13)
            #hash_l = FunctionHash.rol_hash(self.function_hash, 13)
            print(f'[ROR13] {self.function_hash} : {hex(hash_r)}')
            #print(f'[ROL13] {self.function_hash} : 0x{hash_l:08X}')
            exit()
        if self.prep_str != None:
            stack_list = vi.prepare_str_to_stack(self.prep_str)
            #print(f"push 0x{stack_str:08x}")
            for stack_string in stack_list:
                print(stack_string)
            exit()
        self.get_mod_count()
        self.msg('mods')
        self.msg('modules')
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
                
