import importlib
import json

relay_options = ['injection', 'output']

def load_config(file):
    with open(file, "r") as f:
        return json.load(f)

def start_relay(module_name=str, payload_buffer=bytes):
    conf = load_config('module_config.json')
    mod = importlib.import_module(f'modules.{module_name}')
    if module_name == 'injection':
        modclass = mod.inject(payload_buffer, **conf['injection'])
    elif module_name == 'output':
        #modclass = mod.format_shellcode(payload_buffer, 'inspect', 16, False, False, False)
        modclass = mod.format_shellcode(payload_buffer, **conf['output'])
    # elif module_name == 'xor':
    #     modclass = mod.xor_encoder('', '', 0, False, 'encode', None)

    modclass.process()
    
