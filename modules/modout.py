from utils.helper import nstate as nstate

CATEGORY = 'debug'

def register_arguments(parser):
      parser.add_argument('-i', '--input', help='Input file for formatted output')
      parser.add_argument('-s', '--syntax', choices=['c','casm','cs','ps1','py','hex','inspect'], help='formatting the shellcode in C, Casm, C#, Powershell, python or hex')
      parser.add_argument('-l', '--lines', action='store_true', default=False, help='adds a line numbering after each 8 bytes')
      parser.add_argument('-b', '--bytes-per-row', required=False, default=16, type=int, help='Define how many bytes per row will be displayed')
      parser.add_argument('-d', '--decimal', action='store_true', required=False, default=False, help='Output decimal offsets instead of hex')
      parser.add_argument('-n', '--no-line-break', action='store_true', default=False, help='no line break during output')
      #parser.add_argument('-w', '--write', help='write output to the given filename (replacing $%%BUFFER%%$ placeholder in the file')

class format_shellcode:
    Author = 'psycore8'
    Description = 'create formatted output by filename'
    Version = '0.0.2'
    file_bytes = bytes
    offset_color = nstate.clLIGHTMAGENTA

    def __init__(self, input_file=str, syntax=str, lines=bool, bytes_per_row=int, decimal=bool, no_line_break=bool):
        self.input_file = input_file
        self.syntax = syntax
        self.lines = lines
        self.bytes_per_row = bytes_per_row
        self.decimal = decimal
        self.no_line_break = no_line_break
 
    def LoadInputFile(self):
        with open(self.input_file, 'rb') as file:
            self.file_bytes = file.read()

    def GenerateOutput(self):
        formatted_bytes = self.GenerateHeader()
        offset = ''
        s = self.lang[self.syntax]
        for i in range(0, len(self.file_bytes), self.bytes_per_row):
            if self.lines:
                offset = self.GenerateOffset(i)
            chunk = self.file_bytes[i:i+self.bytes_per_row]
            formatted_row = ''.join(f'{s['byte_sep']}{byte:02x}' for byte in chunk)
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
            # header = f"""
            #         File: {self.input_file}
            #         Size: {len(self.file_bytes)}

            #         {head}

            #         """
        return head
    
    def GenerateOffset(self, counter=int):
        c = self.offset_color
        if self.decimal:
            offset = f'{c}{counter:08d}:{nstate.ENDC}'
        else:
            offset = f'{c}{counter:08X}:{nstate.ENDC}'
        return offset

    def PostProcess(self, byte_str):
        pass

    def process(self):
        if self.syntax == 'inspect':
            self.lines = True
        self.LoadInputFile()
        return self.GenerateOutput()
        
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