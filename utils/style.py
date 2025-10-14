import re

from utils.helper import CheckFile, GetFileInfo, sizeof_fmt

from rich.console import Console
from rich.table import Table

cs = Console()

class ConsoleStyles:

    def __init__(self):
        pass

    state_ok        = '[bold grey42][[green]+[/green]][/]'
    state_note      = '[bold grey42][[purple]*[/purple]][/]'
    state_fail      = '[bold grey42][[red]-[/red]][/]'
    state_info      = '[bold grey42][[blue]#[/blue]][/]'

    def module_header(self, ModHeadText, ModVersion):
        f = f'[bold][grey42][[red]{ModHeadText}[/red]]-[[red]{ModVersion}[/red]][/grey42][/bold]'
        cs.print(f)
        #return f
    
    #class actions:
    def action_open_file(self, filename):
        size, hash = GetFileInfo(filename)
        cs.print(f'{self.state_ok} [cyan][u]{filename}[/u][/cyan] - loaded')
        cs.print(f'{self.state_info} File size: [cyan]{size}[/cyan] bytes')
        cs.print(f'{self.state_info} File hash: [cyan]{hash}[/cyan]')

    def action_open_file2(sekf, filename):
        size, hash = GetFileInfo(filename)
        table = Table(border_style='grey42')
        table.add_column('[red]Key[/]', style='red')
        table.add_column('Value')
        #table.add_column('Hash')
        #table.add_row(filename, str(size), hash)
        table.add_row('File', filename)
        table.add_row('Size', str(sizeof_fmt(size)))
        table.add_row('Hash', hash)
        cs.print(table)
        
    def action_save_file(self, filename):
        if CheckFile(filename):
            size, hash = GetFileInfo(filename)
            cs.print(f'{self.state_ok} [cyan][u]{filename}[/u][/cyan] - saved')
            cs.print(f'{self.state_info} File size: [cyan]{size}[/cyan] bytes')
            cs.print(f'{self.state_info} File hash: [cyan]{hash}[/cyan]')
        else:
            cs.print(f'{self.state_fail} {filename } not found!')
            return False
        
    def action_save_file2(self, filename):
        if CheckFile(filename):
            size, hash = GetFileInfo(filename)
            table = Table(border_style='grey42')
            table.add_column('[red]Key[/]', style='red')
            table.add_column('Value')
            #table.add_column('Hash')
            #table.add_row(filename, str(size), hash)
            table.add_row('File', filename)
            table.add_row('Size', str(sizeof_fmt(size)))
            table.add_row('Hash', hash)
            cs.print(table)
        else:
            cs.print(f'{self.state_fail} {filename } not found!')
            return False
        
    def print(self, text:str, state:str=None, rules:bool=False):
        if state == None: state = ''
        message = f'{state} {text}'
        if rules:
            cs.rule('')
            cs.print(message)
            cs.rule('')
        else:
            cs.print(message)

    def log(self, message):
        cs.log(message)


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