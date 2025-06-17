import ast
import importlib
from keystone import *
from utils.const import *
from utils.helper import nstate
from os import path, get_terminal_size, listdir

#import readline
#import rlcompleter
#readline.parse_and_bind("tab: complete")


help_list = {
    'asm':      { 'desc': 'Assemble shellcode instructions: asm "nop; mov ecx, 1"' },
    'exit':     { 'desc': 'Exit ShenCode' },
    'help':     { 'desc': 'List available commands' },
    'list':     { 'desc': 'List available modules' },
    'load':     { 'desc': 'Load a module' },
    'options':  { 'desc': 'List module options' },
    'run':      { 'desc': 'Run module' },
    'set':      { 'desc': 'Set module options' }
}

arg_list = {}
loaded_module = None

left_just = 25
shell_prefix = 'shencode'
shell_infix = ''
shell_suffix = '$ '

def command_parser(command):
    split_cmd = command.split(' ')
    if split_cmd[0] == 'help':
        print('\n')
        for help in help_list:
            print(f'{help}'.ljust(left_just) + f'{help_list[help].get('desc')}')
        print('\n')

    elif split_cmd[0] == 'asm':
        asm = ' '.join(split_cmd).replace('asm ', '')
        try:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            code, count = ks.asm(asm)
            print("".join("\\x{:02x}".format(b) for b in code))
        except KsError as e:
            print("ERROR: %s" %e)

    elif split_cmd[0] == 'exit':
        exit()

    # elif split_cmd[0] == 'info':
    #     args = { 'get': True, 'modlist': True, 'function_hash': '', 'interactive': False, 'prep_str': None }
    #     load_mod('info')
        

    elif split_cmd[0] == 'list':
        for file in listdir(module_dir):
            if file.endswith(".py") and not file.startswith("__"):
                result = file.split()
                print(file)

    elif split_cmd[0] == 'load':
        #if path.exists(module_dir)
        load_mod(split_cmd[1])

    elif split_cmd[0] == 'options':
        size = get_terminal_size()
        print('\n')
        print('Option'.ljust(left_just) + 'Value'.ljust(left_just) + 'Help')
        print('-'*size.columns)
        for arg in arg_list:
            print(f'{arg}'.ljust(left_just) + f'{arg_list[arg]['value']}'.ljust(left_just) + f'{arg_list.get(arg)['desc']}')
        print('\n')

    elif split_cmd[0] == 'run':
        args = {}
        for arg in arg_list:
            args[arg] = arg_list[arg]['value']
        #arg_list
        mod = loaded_module.module(**args)
        mod.process()

    elif split_cmd[0] == 'set':
        cmd = ' '.join(split_cmd).replace(f'set {split_cmd[1]} ', '')
        try:
            evaluated_data = eval_data_types(cmd)
            arg_list[split_cmd[1]]['value'] = evaluated_data
            print(f'{split_cmd[1].upper()} set to {cmd}')
        except KeyError:
            print(f'{split_cmd[1]} is not a valid field')

    else:
        print(f'Sorry, {split_cmd[0]} is unknown...')
    interactive_mode()

def eval_data_types(user_input):
    #key_data_type = ast.literal_eval(arg_list.get(json_key))
    try:
        result = ast.literal_eval(user_input)
    except Exception as e:
        print(f'DEBUG: an error has occured, during type evaluation: {e}')
        result = user_input
    #print(result)
    return result
    # if isinstance(data, key_data_type):
    #     return 
    # else:
    #     return False
        
def set_shell_string():
    pass

def load_mod(module):
    global arg_list, loaded_module, shell_infix
    loaded_module = importlib.import_module(f'{module_dir}.{module}')
    shell_infix = loaded_module.module.shell_path
    arg_list = loaded_module.arglist

def interactive_mode():
    cmd = input(f'{nstate.BOLD}{nstate.clGRAY}{shell_prefix}{shell_infix}{shell_suffix}{nstate.ENDC}')
    command_parser(cmd)
    interactive_mode()


