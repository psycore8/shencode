########################################################
### Task Module
### Status: cleaned, 085
### 
########################################################

#from utils.helper import nstate as nstate
from utils.style import *
from utils.helper import CheckFile, GetFileHash

CATEGORY    = 'core'
DESCRIPTION = 'Create tasks to automate ShenCode'

def register_arguments(parser):
      parser.add_argument('-i', '--input', help='Input task file')

class module:
    import json
    import importlib
    Author = 'psycore8'
    DisplayName = 'TASKS'
    Version = '0.1.1'
    result = any

    def __init__(self, input):
        self.input = input

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
                'pre.head'         : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
                'task.name'        : f'{s_note} Starting Task: {MsgVar}',
                'proc.input'       : f'{s_note} Task file ok',
                'error.input'      : f'{s_fail} Task file failed!',
                'post.done'        : f'{s_ok} Task DONE!',
                'step.pre'         : f'{s_note} Executing step {MsgVar}',
                'nl'               : f'\n'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def load_config(self, file):
        with open(file, "r") as f:
            return self.json.load(f)

    def process(self):
        m = self.msg
        m('pre.head')
        if CheckFile(self.input):
            m('proc.input')
            self.result = None
            tasks = self.load_config(self.input)
            m('task.name', tasks['task']['name'])
            m('nl')
            single_step = tasks['task']['single_step']
            task = tasks['task']['modules']
            mod_count = len(task)
            if single_step == None:
                for index, step in enumerate(task, start=1):
                    if step == 'task' or step == 'bypass':
                        continue
                    m('step.pre', f'{step} // {index} of {mod_count}')
                    m('nl')
                    mod = self.importlib.import_module(f'modules.{step}')
                    if task[step]['input_buffer']:
                        task[step]['args']['input'] = self.result
                        mod.module.relay = True
                        mod.module.relay_input = True
                    if task[step]['return_buffer']:
                        mod.module.relay = True
                        mod.module.relay_output = True
                    modclass = mod.module(**task[step]['args'])
                    self.result = modclass.process()
                    m('nl')
            else:
                mod = self.importlib.import_module(f'modules.{single_step}')
                modclass = mod.module(**task[single_step]['args'])
                modclass.process()
            m('post.done')
        else:
            m('error.input', None, True)
