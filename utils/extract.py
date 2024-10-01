import utils.arg
from utils.helper import nstate as nstate
from os import path as os_path

class extract_shellcode:
    Author =      'psycore8'
    Description = 'extract shellcode from/to pattern'
    Version =     '1.0.0'

    def init():
        spName = 'extract'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for example module'],
            ['-o', '--output', '', '', 'Output file with extracted bytes'],
            ['-fb', '--first-byte', '', '', 'extract from here'],
            ['-lb', '--last-byte', '', '', 'extract until here']
            ]
        utils.arg.CreateSubParser(spName, extract_shellcode.Description, spArgList)

    def process(inputfile, outputfile, first_byte, last_byte):
        print(f"{nstate.OKBLUE} try to open file")
        filename = inputfile
        short_fn = os_path.basename(filename)
        try:
            with open(filename, "rb") as file:
                shellcode = file.read()
                print(f"{nstate.OKGREEN} reading {short_fn} successful!")
        except FileNotFoundError:
            print(f"{nstate.FAIL} file not found, exit")
            exit()
        print(f"{nstate.OKBLUE} cutting shellcode from {first_byte} to {last_byte}")
        shellcode_new = shellcode[int(first_byte):int(last_byte)]
        with open(outputfile, 'wb') as file:
            file.write(shellcode_new)
        path = outputfile
        cf = os_path.isfile(path)
        short_fn = os_path.basename(outputfile)
        if cf == True:
            print(f"{nstate.OKGREEN} written shellcode to {short_fn}")
        else:
            print(f"{nstate.FAIL} error while writing")
            exit()