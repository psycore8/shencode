import re

#from rich import Console

class ConsoleStyles:

    def __init__(self):
        pass

    state_ok        = '[bold white][[green]+[/green]][/bold white]'
    state_note      = '[bold white][[purple]+[/purple]][/bold white]'
    state_fail      = '[bold white][[red]+[/red]][/bold white]'
    state_info      = '[bold white][[yellow]+[/yellow]][/bold white]'

    def FormatModuleHeader(self, ModHeadText, ModVersion):
        f = f'[bold][grey][[red]{ModHeadText}[/red]]-[[red]{ModVersion}[/red]][/grey][/bold]'
        return f

s_ok    = '\033[90m[\033[92m+\033[90m]\033[0m'
s_note  = '\033[90m[\033[94m*\033[90m]\033[0m'
s_fail  = '\033[90m[\033[91m-\033[90m]\033[0m'
s_info  = '\033[90m[\033[95m#\033[90m]\033[0m'
f_link  = '\033[94m\033[4m'
f_out   = '\033[90m[\033[95m#\033[90m]\033[0m'
f_ul    = '\033[4m'
f_bold  = '\033[1m'
f_end   = '\033[0m'
HEADER = '\033[95m'
OKBLUE = '\033[94m[*]\033[0m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m[+]\033[0m'
INFO    = '\033[93m[i]\033[0m'
WARNING = '\033[93m'
FAIL = '\033[91m[-]\033[0m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
LINK = '\033[94m\033[4m'
clLIGHTBLUE = '\033[36m'
clRED = '\033[91m'
clGRAY = '\033[90m'
clLIGHTMAGENTA = '\033[95m'

def FormatModuleHeader(ModHeadText, ModVersion):
    f = f'{f_bold}{clGRAY}[{clRED}{ModHeadText}{clGRAY}]-[{clRED}{ModVersion}{clGRAY}]{f_end}'
    return f

def TextBlue(TextToFormat:str) -> str:
    return f'\033[94m{TextToFormat}\033[0m'

def TextLink(TextToFormat:str) -> str:
    return f'\033[94m\033[4m{TextToFormat}\033[0m'

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def m(mtype):
    messages = {
        'done': '\033[92m[+]\033[0m DONE!'
    }
    print(messages.get(mtype, 'Unknown Message'))