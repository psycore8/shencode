########################################################
### Output Module
### Status: migrated 084
### 
########################################################

from keystone import *
from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileHash

CATEGORY    = 'core'
DESCRIPTION = 'Output and inspect binaries in different formats'

arglist = {
    'input':            { 'value': None, 'desc': 'Input file or buffer for formatted output' },
    'syntax':           { 'value': '', 'desc': 'Formatting the shellcode in C, Casm, C#, Powershell, python or hex' },
    'bytes_per_row':    { 'value': 16, 'desc': 'Define how many bytes per row will be displayed' },
    'decimal':          { 'value': False, 'desc': 'Output decimal offsets instead of hex' },
    'highlight':        { 'value': None, 'desc': 'Highlights bytes' },
    'lines':            { 'value': False, 'desc': 'Adds a line numbering after each 8 bytes' },
    'range':            { 'value': [0,0], 'desc': 'Set a range of bytes to output: <start> <end>' },
    'no_line_break':    { 'value': False, 'desc': 'No line break during output' },
    'output':           { 'value': None, 'desc': 'Save output to file' }
}

def register_arguments(parser):
      parser.add_argument('-i', '--input', help=arglist['input']['desc'])
      parser.add_argument('-s', '--syntax', choices=['asm','c','casm','cs','ps1','py','hex','inspect'], help=arglist['syntax']['desc'])

      src = parser.add_argument_group('formatting')
      src.add_argument('-b', '--bytes-per-row', required=False, default=16, type=int, help=arglist['bytes_per_row']['desc'] , metavar='INT')
      src.add_argument('-hl', '--highlight', default=None, help=arglist['highlight']['desc'])
      src.add_argument('-n', '--no-line-break', action='store_true', default=False, help=arglist['no_line_break']['desc'])
      src.add_argument('-r', '--range', nargs=2, default=[0, 0], type=int, help=arglist['range']['desc'])

      grp = parser.add_argument_group('additional')
      grp.add_argument('-d', '--decimal', action='store_true', required=False, default=False, help=arglist['decimal']['desc'])
      grp.add_argument('-l', '--lines', action='store_true', default=False, help=arglist['lines']['desc'])
      grp.add_argument('-o', '--output', required=False, type=str, default=None, help=arglist['output']['desc'])

class module:
    Author = 'psycore8'
    DisplayName = 'MODOUT'
    Version = '0.2.5'
    file_bytes = bytes
    offset_color = nstate.clLIGHTMAGENTA
    cFile = False
    shell_path = '::core::output'

    # arglist = {
    #     'input':            { 'val': None, 'dt': str },
    #     'syntax':           { 'val': '', 'dt': str },
    #     'bytes_per_row':    { 'val': 16, 'dt': int },
    #     'decimal':          { 'val': False, 'dt': bool },
    #     'highlight':        { 'val': None, 'dt': bool },
    #     'lines':            { 'val': False, 'dt': bool },
    #     'range':            { 'val': [None, None], 'dt': list }, 
    #     'no_line_break':    { 'val': False, 'dt': bool },
    #     'output':           { 'val': None, 'dt': str }
    # }

    def __init__(self, input=any, syntax=str, bytes_per_row=int, decimal=bool, highlight=None, lines=bool, range=[0, 0], no_line_break=bool, output=None):
        self.input = input
        self.syntax = syntax
        self.lines = lines
        self.bytes_per_row = bytes_per_row
        self.decimal = decimal
        self.highlight = highlight
        self.no_line_break = no_line_break
        if range != [0, 0]:
            self.range = [range[0], range[1]]
        else:
            self.range = [0, 0]
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
            'post.summary'  : f'{nstate.s_info} Total length: {MsgVar} bytes',
            'post.done'     : f'{nstate.s_ok} DONE!',
            'error.input'   : f'{nstate.s_fail} Input file not found' ,
            'error.output'  : f'{nstate.s_fail} Output file not found'
        }
        print(messages.get(message_type, 'Unknown message type'))
        if ErrorExit:
            exit()
 
    def LoadInputFile(self):
        with open(self.input, 'rb') as file:
            if self.range == [0, 0]:
                self.file_bytes = file.read()
            else:
                x = self.range[0]
                y = self.range[1]
                file.seek(x)
                self.file_bytes = file.read(y - x)

    def SaveOutputFile(self, data):
        nstate.remove_ansi_escape_sequences(data)
        with open(self.output, 'w') as file:
            file.write(
                nstate.remove_ansi_escape_sequences( data )
                )

    def highlight_word(self, text, word, colorclass):
        highlighted_text = text.replace(word, f"{colorclass}{word}{nstate.ENDC}")  # Rote Markierung
        return highlighted_text

    def GenerateOutput(self):
        formatted_bytes = self.GenerateHeader()
        offset = ''
        s = self.lang[self.syntax]
        size = len(self.file_bytes)
        for i in range(0, len(self.file_bytes), self.bytes_per_row):
            if self.lines:
                offset = self.GenerateOffset(i)
            chunk = self.file_bytes[i:i+self.bytes_per_row]
            formatted_row = ''.join(f'{s["byte_sep"]}{byte:02x}' for byte in chunk)
            formatted_row = self.highlight_word(formatted_row, '00', nstate.clRED)
            if self.highlight != None:
                formatted_row = self.highlight_word(formatted_row, self.highlight, nstate.clLIGHTBLUE)
            formatted_bytes += f'{offset}{s["row_prefix"]}{formatted_row[s["row_cut"]:]}{s["row_suffix"]}'
        if self.no_line_break:
            formatted_bytes = formatted_bytes.replace('\n', '')
        return f'{formatted_bytes[:s["code_cut"]]}{s["code_add"]}', size

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

    def PostProcess(self):
        pass

    def process(self):
        self.msg('pre.head')
        if self.syntax == 'inspect':
            self.lines = True
        self.msg('pre.input')
        if isinstance(self.input, str):
            CheckFile(self.input)
            self.LoadInputFile()
            self.msg('pre.hash', False, GetFileHash(self.input))
        elif isinstance(self.input, bytes):
            self.file_bytes = self.input
        else:
            self.msg('error.input', True)
        if self.syntax == 'asm':
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                self.file_bytes, count = ks.asm(self.file_bytes)
                print(f'{self.file_bytes} // {count}')
            except KsError as e:
                print("ERROR: %s" %e)
        self.msg('process')
        output, size = self.GenerateOutput()
        if not self.output == None:
            self.SaveOutputFile(output)
            if CheckFile(self.output):
                self.msg('post.output')
            else:
                self.msg('error.output', True)
        print(output)
        self.msg('post.summary', False, size)
        self.msg('post.done')
        
    lang = {
        'asm': {
            'code_begin':   '',
            'byte_sep':     '\\x',
            'row_prefix':   '',
            'row_suffix':   '\n',
            'row_cut':      None,
            'code_add':     '',
            'code_cut':     None
        },
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