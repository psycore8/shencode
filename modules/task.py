########################################################
### AES Module
### Status: untested
########################################################

from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileHash

CATEGORY = 'core'

def register_arguments(parser):
      parser.add_argument('-i', '--input', help='Input task file')

class module:
    import json
    import importlib
    Author = 'psycore8'
    Description = 'Create tasks to pipe ShenCode modules'
    DisplayName = 'TASKS'
    Version = '0.0.4'
    result = any

    def __init__(self, input):
        self.input = input

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
                'pre.head'         : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
                'task.name'        : f'{nstate.s_note} Starting Task: {MsgVar}',
                'proc.input'       : f'{nstate.s_note} Task file ok',
                'error.input'      : f'{nstate.s_fail} Task file failed!',
                'post.done'        : f'{nstate.s_ok} Task DONE!',
                'step.pre'         : f'{nstate.s_note} Executing step',
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
            task = self.load_config(self.input)
            m('task.name', task['task']['name'])
            m('nl')
            for step in task:
                if step != 'task':
                    mod = self.importlib.import_module(f'modules.{step}')
                    if task[step]['input_buffer']:
                        task[step]['args']['input'] = self.result
                        mod.module.relay = True
                    if task[step]['return_buffer']:
                        mod.module.relay = True
                    modclass = mod.module(**task[step]['args'])
                    self.result = modclass.process()
                    m('nl')
            m('post.done')
        else:
            m('error.input', None, True)
