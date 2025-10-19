########################################################
### ShenCode Module
###
### Name: Task
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from utils.helper import CheckFile

CATEGORY    = 'core'
DESCRIPTION = 'Create tasks to automate ShenCode (V2 scheme)'

cs = ConsoleStyles()

def register_arguments(parser):
      parser.add_argument('-i', '--input', help='Input task file')

class module:
    import json
    import importlib
    Author = 'psycore8'
    DisplayName = 'TASKS-V2'
    Version = '0.9.0'
    result = any

    def __init__(self, input):
        self.input = input

    def load_config(self, file):
        with open(file, "r") as f:
            return self.json.load(f)

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        if CheckFile(self.input):
            self.result = None
            tasks = self.load_config(self.input)
            try:
                if tasks['scheme'] != 'V2':
                    cs.console_print.error('Wrong task scheme! This module requires [bold red]V2[/] scheme!')
            except KeyError:
                cs.console_print.error('Wrong task scheme! This module requires [bold red]V2[/] scheme!')
                return
            cs.print('Task file ok', cs.state_ok)
            cs.print(f'Starting Task: {tasks['name']}\n', cs.state_note)
            single_step = tasks['single_step']
            if single_step == None:
                for task in tasks["tasks"]:
                    cs.print(f'Executing step #{task["id"]}', cs.state_note)
                    cs.rule(f'[bold red]{task["module"]}[/]')
                    mod = self.importlib.import_module(f'modules.{task["module"]}')
                    if task["input_buffer"]:
                        task["args"]["input"] = self.result
                        mod.module.relay = True
                        mod.module.relay_input = True
                    if task["return_buffer"]:
                        task["args"]["output"] = self.result
                        mod.module.relay = True
                        mod.module.relay_output = True
                    modclass = mod.module(**task["args"])
                    self.result = modclass.process()
                    cs.print('\n')
            else:
                mod = self.importlib.import_module(f'modules.{single_step}')
                modclass = mod.module(**task[single_step]['args'])
                modclass.process()
            cs.print('Task DONE!', cs.state_ok)
        else:
            cs.print('Task file failed!', cs.state_fail)
            return
