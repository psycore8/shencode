from utils.hashes import sha1
from os import path

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

class FileCheck:
    def CheckWrittenFile(file, module_message):
        cf = path.isfile(file)
        if cf:
            hash = sha1.calculate_sha1(file)
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