########################################################
### Output Module
### Status: migrated to 081
########################################################

from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileHash

CATEGORY = 'core'

def register_arguments(parser):
      #parser.add_argument('-i', '--input', help='Input file for formatted output')
      parser.add_argument('-i', '--input', help='Input file or buffer for formatted output')
      #parser.add_argument('-it', '--input-type', choices=['file', 'buffer'], default='file', help='Specify input type')
      parser.add_argument('-s', '--syntax', choices=['c','casm','cs','ps1','py','hex','inspect'], help='formatting the shellcode in C, Casm, C#, Powershell, python or hex')

      grp = parser.add_argument_group('additional')
      grp.add_argument('-b', '--bytes-per-row', required=False, default=16, type=int, help='Define how many bytes per row will be displayed', metavar='INT')
      grp.add_argument('-d', '--decimal', action='store_true', required=False, default=False, help='Output decimal offsets instead of hex')
      grp.add_argument('-l', '--lines', action='store_true', default=False, help='adds a line numbering after each 8 bytes')
      grp.add_argument('-n', '--no-line-break', action='store_true', default=False, help='no line break during output')
      grp.add_argument('-o', '--output', required=False, type=str, default=None, help='save output to file')

class module:
    Author = 'psycore8'
    Description = 'create formatted output by filename'
    DisplayName = 'MODOUT'
    Version = '0.1.5'
    file_bytes = bytes
    offset_color = nstate.clLIGHTMAGENTA
    cFile = False


    def __init__(self, input=any, syntax=str, bytes_per_row=int, decimal=bool, lines=bool, no_line_break=bool, output=None):
        self.input = input
        #self.input_type = input_type
        self.syntax = syntax
        self.lines = lines
        self.bytes_per_row = bytes_per_row
        self.decimal = decimal
        self.no_line_break = no_line_break
        #self.output_type = output_type
        #self.output_buffer = output_buffer
        self.output = output
        if not output == '':
            self.cFile = True

    def msg(self, message_type, ErrorExit=False, MsgVar=None):
        messages = {
            'pre.head'      : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'pre.input'     : f'{nstate.s_note} Input File: {self.input}',
            'pre.hash'      : f'{nstate.f_out} File Hash: {MsgVar}',
            'process'       : f'{nstate.s_note} processing shellcode format... NoLineBreak: {self.no_line_break}\n',
            'post.output'   : f'{nstate.s_ok} Output file: {self.output}',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'error.input'   : f'{nstate.s_fail} Input file not found' ,
            'error.output'  : f'{nstate.s_fail} Output file not found'
        }
        print(messages.get(message_type, 'Unknown message type'))
        if ErrorExit:
            exit()
 
    def LoadInputFile(self):
        with open(self.input, 'rb') as file:
            self.file_bytes = file.read()

    def SaveOutputFile(self, data):
        nstate.remove_ansi_escape_sequences(data)
        with open(self.output, 'w') as file:
            file.write(
                nstate.remove_ansi_escape_sequences( data )
                )

    def GenerateOutput(self):
        formatted_bytes = self.GenerateHeader()
        offset = ''
        s = self.lang[self.syntax]
        for i in range(0, len(self.file_bytes), self.bytes_per_row):
            if self.lines:
                offset = self.GenerateOffset(i)
            chunk = self.file_bytes[i:i+self.bytes_per_row]
            #chunk = self.GenerateHighlight(chunk)
            formatted_row = ''.join(f'{s['byte_sep']}{byte:02x}' for byte in chunk)
            #formatted_row = self.GenerateHighlight(formatted_row)
            formatted_bytes += f'{offset}{s['row_prefix']}{formatted_row[s['row_cut']:]}{s['row_suffix']}'
        if self.no_line_break:
            formatted_bytes = formatted_bytes.replace('\n', '')
        return f'{formatted_bytes[:s['code_cut']]}{s["code_add"]}'

    def GenerateHeader(self):
        if not self.syntax == 'inspect':
            head = ''
        else:
            c = self.offset_color
            if self.decimal:
                row_numbers = ' '.join(f'{i:02d}' for i in range(self.bytes_per_row))
                head = f'{c}Offset(d) {row_numbers}{nstate.ENDC}\n'
            else:
                row_numbers = ' '.join(f'{i:02X}' for i in range(self.bytes_per_row))
                head = f'{c}Offset(h) {row_numbers}{nstate.ENDC}\n'
        return head
    
    def GenerateOffset(self, counter=int):
        c = self.offset_color
        if self.decimal:
            offset = f'{c}{counter:08d}:{nstate.ENDC}'
        else:
            offset = f'{c}{counter:08X}:{nstate.ENDC}'
        return offset

    # def GenerateHighlight(self, text):
    #     result = ''
    #     x = len(text)//2
    #     result = text[:x] + f'{nstate.OKCYAN}' + text[x+1:x+1] + f'{nstate.ENDC}' + text[x+1-1:]
    #     # for i, char in enumerate(text, start=1):
    #     #     if i % 10 == 0 or i % 10 == 1:
    #     #         result += f'{nstate.OKCYAN}{char}{nstate.ENDC}'
    #     #     else:
    #     #         result += char
    #     #result = text + result
    #     return result

    def PostProcess(self):
        pass

    def process(self):
        self.msg('pre.head')
        if self.syntax == 'inspect':
            self.lines = True
        self.msg('pre.input')
        #if self.input_type == 'file':
        if isinstance(self.input, str):
            CheckFile(self.input)
            self.LoadInputFile()
            self.msg('pre.hash', False, GetFileHash(self.input))
        elif isinstance(self.input, bytes):
            self.file_bytes = self.input
        else:
            self.msg('error.input', True)
        self.msg('process')
        output = self.GenerateOutput()
        if not self.output == None:
            self.SaveOutputFile(output)
            if CheckFile(self.output):
                self.msg('post.output')
            else:
                self.msg('error.output', True)
        print(output)
        self.msg('post.done')
        #return output
        
    lang = {
        'c': {
            'code_begin':   '',
            'byte_sep':     '\\x',
            'row_prefix':   '\"',
            'row_suffix':   '\"\n',
            'row_cut':      None,
            'code_add':     ';',
            'code_cut':     -1
        },
        'casm': {
            'code_begin':   '',
            'byte_sep':     ',0x',
            'row_prefix':   '\".byte ',
            'row_suffix':   '\\n\\t\"\n',
            'row_cut':      1,
            'code_add':    '\"ret\\n\\t\"',
            'code_cut':    None
        },
        'cs': {
            'code_begin':   '',
            'byte_sep':     ',0x',
            'row_prefix':   '',
            'row_suffix':   '\n',
            'row_cut':      1,
            'code_add':    '\n',
            'code_cut':     -1
        },
        'ps1': {
            'code_begin':   '',
            'byte_sep':     ',0x',
            'row_prefix':   '',
            'row_suffix':   '\n',
            'row_cut':      1,
            'code_add':    '\n',
            'code_cut':     -1
        },
        'py': {
            'code_begin':   '',
            'byte_sep':     '\\x',
            'row_prefix':   'buf += b\'',
            'row_suffix':   '\'\n',
            'row_cut':      None,
            'code_add':    '\n',
            'code_cut':     None
        },
        'hex': {
            'code_begin':   '',
            'byte_sep':     '',
            'row_prefix':   '',
            'row_suffix':   '\n',
            'row_cut':      None,
            'code_add':    '',
            'code_cut':     None
        },
        # 'base64': {
        #     'code_begin':   '',
        #     'byte_sep':     '',
        #     'row_prefix':   '',
        #     'row_suffix':   '',
        #     'row_cut':      None,
        #     'code_add':    '',
        #     'code_cut':     None
        # },
        'inspect': {
            'code_begin':   '',
            'byte_sep':     ' ',
            'row_prefix':   '',
            'row_suffix':   '\n',
            'row_cut':      None,
            'code_add':    '',
            'code_cut':     None
        }
    }