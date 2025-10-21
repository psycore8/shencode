from utils.hashes import sha1
from os import name, path, rename, stat
import re

def CheckFile(file):
    cf = path.isfile(file)
    if cf:
        return True
    else:
        return False
    
def GetFSize(file):
    fs = path.getsize(file)
    return fs
    
def GetFileHash(file):
    hash = sha1.calculate_sha1(file)
    return f'{hash}'

def GetFileInfo(file):
    size = GetFSize(file)
    hash = f'{sha1.calculate_sha1(file)}'
    return size, hash

# Source: https://stackoverflow.com/questions/1094841/get-a-human-readable-version-of-a-file-size
def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"[cyan]{num:3.1f}[/] {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


class nstate:
    ### [STATUS]-[MODNAME] : Message Extra
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

    def __init__(self):
        pass

    def FormatModuleHeader(self, ModHeadText, ModVersion):
        f = f'{nstate.f_bold}{nstate.clGRAY}[{nstate.clRED}{ModHeadText}{nstate.clGRAY}]-[{nstate.clRED}{ModVersion}{nstate.clGRAY}]{nstate.f_end}'
        return f

    def TextBlue(self, TextToFormat:str) -> str:
        return f'\033[94m{TextToFormat}\033[0m'
    
    def TextLink(self, TextToFormat:str) -> str:
        return f'\033[94m\033[4m{TextToFormat}\033[0m'
    
    def remove_ansi_escape_sequences(self, text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def m(self, mtype):
        messages = {
            'done': '\033[92m[+]\033[0m DONE!'
        }
        print(messages.get(mtype, 'Unknown Message'))

class FileCheck:

    def CheckWrittenFile(self, file, module_message):
        cf = path.isfile(file)
        if cf:
            hash = sha1.calculate_sha1(file)
            #size = self.file_size(file)
            s = [ 
                f'{nstate.OKGREEN} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File created',
                f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File: {file}',
                f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} Hash: {nstate.BOLD}{nstate.clLIGHTBLUE}{hash}{nstate.ENDC}'
            ]
        else:
            s = [ f'{nstate.FAIL} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File not created',
                 f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File: -',
                 f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} Hash: {nstate.BOLD}{nstate.clLIGHTBLUE}-{nstate.ENDC}' ]
        return cf, s
    
    def CheckSourceFile(self, file, module_message):
        cf = path.isfile(file)
        if cf:
            hash = sha1.calculate_sha1(file)
            s = [
                f'{nstate.OKGREEN} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File exists',
                f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File: {file}',
                f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} Hash: {nstate.BOLD}{nstate.clLIGHTBLUE}{hash}{nstate.ENDC}'
            ]
        else:
            s = [ f'{nstate.FAIL} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File does not exist',
                 f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} File: -',
                 f'{nstate.INFO} {nstate.clGRAY}[{module_message}]{nstate.ENDC} Hash: {nstate.BOLD}{nstate.clLIGHTBLUE}-{nstate.ENDC}' ]
        return cf, s
    
class FirstRun:
    def CheckFirstRunState(self):
        file = 'os.done'
        if not path.exists(file):
            if name == 'nt':
                FirstRun.WinOnlyModules(self, True)
                with open(file, 'w') as file:
                    file.write(f'Operating System: {name}')
            else:
                FirstRun.WinOnlyModules(self, False)
                with open(file, 'w') as file:
                    file.write(f'Operating System: {name}')
            print(f'{nstate.OKGREEN} OS Check passed!')

    def WinOnlyModules(self, ActivationState:bool):
        Mod_Dir = 'modules'
        FileList = [ 'injection', 'dll', 'meterpreter', 'minidump', 'ntinjection', 'psoverwrite', 'rolhash' ]
        if ActivationState:
            for file in FileList:
                src_file = f'{Mod_Dir}\\{file}.px'
                dst_file = f'{Mod_Dir}\\{file}.py'
                if path.exists(src_file):
                    rename(src_file,dst_file)
        elif not ActivationState:
            for file in FileList:
                src_file = f'{Mod_Dir}/{file}.py'
                dst_file = f'{Mod_Dir}/{file}.px'
                if path.exists(src_file):
                    rename(src_file,dst_file)
