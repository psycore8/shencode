from utils.hashes import sha1
from os import name, path, rename, stat

class nstate:
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
    clRED = '\033[30m'
    clGRAY = '\033[90m'

    def TextBlue(TextToFormat:str) -> str:
        return f'\033[94m{TextToFormat}\033[0m'
    
    def TextLink(TextToFormat:str) -> str:
        return f'\033[94m\033[4m{TextToFormat}\033[0m'

class FileCheck:

    # def __init__(self):
    #     self = self

    # # https://stackoverflow.com/a/39988702
    # def convert_bytes(self, num):
    #     """
    #     this function will convert bytes to MB.... GB... etc
    #     """
    #     for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
    #         if num < 1024.0:
    #             return f'{num: 1f} {x}'
    #             #return "%3.1f %s" % (num, x)
    #         num /= 1024.0

    # def file_size(self, file_path):
    #     """
    #     this function will return the file size
    #     """
    #     if path.isfile(file_path):
    #         file_info = stat(file_path)
    #         return convert_bytes(file_info.st_size)

    def CheckWrittenFile(file, module_message):
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
    
    def CheckSourceFile(file, module_message):
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
    def CheckFirstRunState():
        file = 'os.done'
        if not path.exists(file):
            if name == 'nt':
                FirstRun.WinOnlyModules(True)
                with open(file, 'w') as file:
                    file.write(f'Operating System: {name}')
            else:
                FirstRun.WinOnlyModules(False)
                with open(file, 'w') as file:
                    file.write(f'Operating System: {name}')
            print(f'{nstate.OKGREEN} OS Check passed!')

    def WinOnlyModules(ActivationState:bool):
        Mod_Dir = 'modules'
        FileList = [ 'injection', 'meterpreter', 'sliver', 'rolhash' ]
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
