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
    Version = '0.0.2'
    result = any

    def __init__(self, input):
        self.input = input

    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
                'pre.head'         : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
                'proc.input'       : f'{nstate.s_note} Task file ok',
                'create.cfg'       : f'{nstate.f_out} CFGuard mitigation will be applied!',
                'create.try'       : f'{nstate.s_note} Create suspended Process...',
                'create.error'     : f'{nstate.s_fail} CreateProcess failed',
                'step.post'        : f'\n'
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
            #steps = len(task)
            for step in task:
                #print(f'{step}')
                if step != 'task':
                    mod = self.importlib.import_module(f'modules.{step}')
                    if task[step]['input'] == '$BUFFER$':
                        task[step]['input'] = self.result
                    modclass = mod.module(**task[step])
                    modclass.relay = True
                    self.result = modclass.process()
                    m('step.post')
        else:
            pass
