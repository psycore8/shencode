import ast
import importlib
import json
import shlex
from keystone import *
from utils.crypt import aes_worker
from utils.const import *
from utils.helper import nstate
from os import path, get_terminal_size, listdir

from prompt_toolkit import prompt, styles
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML

n = nstate
print(f'{n.clRED}Interactive mode is still experimental{n.ENDC}')
print(f'For error reporting use: {n.f_link}https://github.com/psycore8/shencode{n.ENDC}')

cmd = ''

help_list = {
    'aeskey':       { 'desc': 'Generate an AES key, iv and salt: aeskey password' },
    'asm':          { 'desc': 'Assemble shellcode instructions: asm "nop; mov ecx, 1"' },
    'config':       { 'desc': 'Save or restore module configuration (overwrites old configs): config save/restore' },
    'exit':         { 'desc': 'Exit ShenCode' },
    'help':         { 'desc': 'List available commands' },
    'list':         { 'desc': 'List available modules' },
    'load':         { 'desc': 'Load a module' },
    'options':      { 'desc': 'List module options' },
    'run':          { 'desc': 'Run module' },
    'set':          { 'desc': 'Set module options' }
}

auto_complete = []

imods = {
    'core':         [ 'download', 'extract', 'multicoder', 'output' ],
    'encoder':      [ 'alphanum', 'bytebert' ],
    'inject':       [ 'dll', 'inject', 'psoverwrite' ],
    'obfuscate':    [ 'feed', 'qrcode', 'rolhash', 'uuid' ],
    'payload':      [ 'msfvenom', 'winexec' ],
    'stager':       [ 'meterpreter', 'sliver' ]
}

append_keywords = [ 'save', 'restore' ]

arg_list = {}
loaded_module = None
loaded_module_name = None

left_just = 25
shell_prefix = 'shencode'
shell_infix = ''
shell_suffix = '$ '

style = styles.Style.from_dict({
    # 'token': 'fg:bg bold italic underline'
    'prompt': 'bold fg:magenta',  # grün und fett
})

def command_parser(command):
    global arg_list, loaded_module_name
    #print(f'DEBUG: {arg_list}')
    #split_cmd = command.split(' ')
    #lex = shlex.shlex(command, posix=False)
    split_cmd = shlex.split(command, posix=False)
    #print(f'DEBUG: {split_cmd}')
    if split_cmd[0] == 'help':
        print('\n')
        for help in help_list:
            print(f'{help}'.ljust(left_just) + f'{help_list[help].get("desc")}')
        print('\n')

    elif split_cmd[0] == 'asm':
        #asm = ' '.join(split_cmd).replace('asm ', '')
        asm = shlex.join(split_cmd).replace('asm ', '')
        try:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            code, count = ks.asm(asm)
            print("".join("\\x{:02x}".format(b) for b in code))
        except KsError as e:
            print("ERROR: %s" %e)

    elif split_cmd[0] == 'config':
        if split_cmd[1] == 'save':
            if loaded_module != None:
                fn = f'{json_dir}{loaded_module_name}.json'
                with open(fn, 'w') as f:
                    json.dump(arg_list, f, ensure_ascii=False, indent=4)
            else:
                print('No module loaded. Use the load command before.')
        elif split_cmd[1] == 'restore':
            if loaded_module != None:
                fn = f'{json_dir}{loaded_module_name}.json'
                try:
                    with open(fn, 'r') as f:
                        arg_list = json.load(f)
                except FileNotFoundError as e:
                    print(f'ERROR: {e}')
            else:
                print('No module loaded. Use the load command before.')
        else:
            print('The given argument was not recognized, use save or restore.')

    elif split_cmd[0] == 'exit':
        exit()
        
    elif split_cmd[0] == 'list':
        for mod in imods:
            for submod in imods[mod]:
                result = f'{mod}'.ljust(10).upper() + f'- {submod}'
                print(result)


    elif split_cmd[0] == 'load':
        load_mod(split_cmd[1])
        loaded_module_name = split_cmd[1]

    elif split_cmd[0] == 'options':
        size = get_terminal_size()
        print('\n')
        print('Option'.ljust(left_just) + 'Value'.ljust(left_just) + 'Help')
        print('-'*size.columns)
        for arg in arg_list:
            print(f'{arg}'.ljust(left_just) + f'{arg_list[arg]["value"]}'.ljust(left_just) + f'{arg_list.get(arg)["desc"]}')
        print('\n')

    elif split_cmd[0] == 'run':
        args = {}
        for arg in arg_list:
            args[arg] = arg_list[arg]['value']
        mod = loaded_module.module(**args)
        mod.process()

    elif split_cmd[0] == 'set':
        #cmd = ' '.join(split_cmd).replace(f'set {split_cmd[1]} ', '')
        cmd = shlex.join(split_cmd).replace(f'set {split_cmd[1]} ', '')
        try:
            evaluated_data = eval_data_types(cmd)
            arg_list[split_cmd[1]]['value'] = evaluated_data
            print(f'{split_cmd[1].upper()} set to {cmd}')
        except KeyError:
            print(f'{split_cmd[1]} is not a valid field')

    elif split_cmd[0] == 'aeskey':
        aw = aes_worker()
        key = aw.generate_password(32)
        iv = aw.generate_password(16)
        print(f'Key: {key}')
        print(f'IV: {iv}')

    else:
        print(f'Sorry, {split_cmd[0]} is unknown...')
    interactive_mode()

def eval_data_types(user_input):
    try:
        result = ast.literal_eval(user_input)
    except Exception as e:
        #print(f'DEBUG: an error has occured, during type evaluation: {e}')
        result = user_input
    return result
        
def set_shell_string():
    pass

def load_mod(module):
    global arg_list, auto_complete, loaded_module, shell_infix
    auto_complete = []
    for item in help_list:
        auto_complete.append(item)
    try:
        loaded_module = importlib.import_module(f'{module_dir}.{module}')
        shell_infix = loaded_module.module.shell_path
        arg_list = loaded_module.arglist
        for item in append_keywords:
            auto_complete.append(item)
        for arg in arg_list:
            auto_complete.append(arg)
        for module in imods:
            for entry in imods[module]:
                auto_complete.append(entry)
    except Exception as e:
        print(f'Error loading module {module}: {e}')

def interactive_mode():
    prompt_text = HTML('<prompt>Befehl&gt; </prompt>')
    if loaded_module == None:
        for item in append_keywords:
            auto_complete.append(item)
        for item in help_list:
            auto_complete.append(item)
        for module in imods:
            for entry in imods[module]:
                auto_complete.append(entry)
    completer = WordCompleter(auto_complete, ignore_case=True)
    cmd = prompt(f'{shell_prefix}{shell_infix}{shell_suffix}', completer=completer, style=style)
    command_parser(cmd)
    interactive_mode()


