import argparse
import os

class parser:
    args = ''

    #def __init__(self):
        #self.args = args

    def parser_add(self):
        parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
        parser.add_argument("-o", "--output", choices=["c","casm","cs","ps1","py","hex","inspect"], help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
        subparsers = parser.add_subparsers(dest='command')
        parser_create = subparsers.add_parser("create", help="create a shellcode")
        parser_create.add_argument("-c", "--msf-cmd", type=str, help="msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"")
        parser_create.add_argument('-x', '--xor-stub', action='store_true', help='create payload from a raw file, encode with xor, add to xor stub')
        parser_create.add_argument('-f','--xor-filename',help='Input file to us with xor stub')
        parser_create.add_argument('-o', '--xor-outputfile', help='outputfile for xor stub')
        parser_create.add_argument('-k', '--xor-key', help='the XOR key to use')
        parser_encode = subparsers.add_parser("encode", help="encode windows function hashes to ROL")
        parser_encode.add_argument("-f", "--filename", help="raw input file with shellcode")
        parser_encode.add_argument("-o", "--outputfile", help="raw input file with shellcode")
        if os.name == 'nt':
            parser_encode.add_argument("-r", "--ror2rol", action="store_true", help="change ROR13 to ROL encoding")
            parser_encode.add_argument("-rk", "--key", help="ROL key for encoding")
        parser_encode.add_argument("-x", "--xor",   action="store_true", help="use additional XOR encoding")
        parser_encode.add_argument("-xk", "--xorkey", help="XOR key for encoding")
        parser_encode.add_argument("-q", "--qrcode",   action="store_true", help="store your payload in QR Code picture")
        parser_encode.add_argument("-u", "--uuid",   action="store_true", help="Obfuscate Shellcode as UUID")
        parser_encode = subparsers.add_parser("extract", help="extract shellcode from/to pattern")
        parser_encode.add_argument("-f", "--filename", help="inputfile")
        parser_encode.add_argument("-o", "--outputfile", help="outputfile")
        parser_encode.add_argument("-fb", "--first-byte", help="extract from here")
        parser_encode.add_argument("-lb", "--last-byte", help="extract until here")
        if os.name == 'nt':
            parser_inject = subparsers.add_parser("inject", help="inject shellcode")
            parser_inject.add_argument("-f", "--filename", help="raw input file with shellcode to inject")
            parser_inject.add_argument("-p", "--processname", help="raw input file with shellcode to inject")
            parser_inject.add_argument("-s", "--startprocess", action="store_true", help="raw input file with shellcode to inject")
        parser_output = subparsers.add_parser("output", help="create formatted output by filename")
        parser_output.add_argument("-f", "--filename", help="raw input file with shellcode")
        parser_output.add_argument("-s", "--syntax", help="formatting the shellcode in C, Casm, C#, Powershell, python or hex")
        parser_output.add_argument("-l", "--lines", action="store_true", help="adds a line numbering after each 8 bytes")
        parser_output.add_argument("-w", "--write", help="write output to the given filename (replacing $%BUFFER%$ placeholder in the file")
        #parser.args = parser.parse_args(command_line)
        return 0
    
    def start_parsing(commands):
        #parser.args = commands
        parser.args = parser.parser_add.parser.parse_args(commands)
        return 0