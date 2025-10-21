########################################################
### ShenCode Module
###
### Name: Inspect
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *
from rich.table import Table
from rich.console import Console
#from rich.progress import track

CATEGORY    = 'core'
DESCRIPTION = 'Inspect binary files'

cs = ConsoleStyles()
console = Console(record=True)

arglist = {
    'input':            { 'value': None, 'desc': 'Input file or buffer for formatted output' },
    'bytes_per_row':    { 'value': 16, 'desc': 'Define how many bytes per row will be displayed' },
    'decimal':          { 'value': False, 'desc': 'Output decimal offsets instead of hex' },
    'export':           { 'value': None, 'desc': 'Save table as html file' },
    'highlight':        { 'value': None, 'desc': 'Highlights bytes' },
    'range':            { 'value': [0,0], 'desc': 'Set a range of bytes to output: <start> <end>' }
}

def register_arguments(parser):
      parser.add_argument('-i', '--input', help=arglist['input']['desc'])

      src = parser.add_argument_group('formatting')
      src.add_argument('-b', '--bytes-per-row', required=False, default=16, type=int, help=arglist['bytes_per_row']['desc'] , metavar='INT')
      src.add_argument('-hl', '--highlight', default=None, help=arglist['highlight']['desc'])
      src.add_argument('-e', '--export', default=None, help=arglist['export']['desc'])
      src.add_argument('-r', '--range', nargs=2, default=[0, 0], type=int, help=arglist['range']['desc'])
      src.add_argument('-d', '--decimal', action='store_true', required=False, default=False, help=arglist['decimal']['desc'])

class module:
    Author = 'psycore8'
    DisplayName = 'MOD-INSPECT'
    Version = '0.9.0'
    file_bytes = bytes
    cFile = False
    shell_path = '::core::inspect'
    table = Table()

    def __init__(self, input=any, bytes_per_row=int, decimal=bool, export=None, highlight=None, range=[0, 0]):
        self.input = input
        self.bytes_per_row = bytes_per_row
        self.decimal = decimal
        self.export = export
        self.highlight = highlight
        if range != [0, 0]:
            self.range = [range[0], range[1]]
        else:
            self.range = [0, 0]

    def load_input_file(self):
        with open(self.input, 'rb') as file:
            if self.range == [0, 0]:
                self.file_bytes = file.read()
            else:
                x = self.range[0]
                y = self.range[1]
                file.seek(x)
                self.file_bytes = file.read(y - x)

    def highlight_table_word(self, list, word, colorclass):
        delimiter = ' '
        converted_string = delimiter.join(list)
        highlighted_text = converted_string.replace(word, f"{colorclass}{word}[/]")
        converted_list = highlighted_text.split()
        return converted_list
    
    def generate_table_output(self):
        self.table.border_style = 'grey42'
        self.generate_table_header()
        row = []
        for i in range(0, len(self.file_bytes), self.bytes_per_row):
            row.append(self.generate_table_offset(i))
            chunk = self.file_bytes[i:i+self.bytes_per_row]
            for byte in chunk:
                if byte == 0:
                    ctag_open = '[red bold]'
                    ctag_close = '[/]'
                else:
                    ctag_open = ''
                    ctag_close = ''
                row.append(f'{ctag_open}{byte:02x}{ctag_close}')
            if self.highlight != None:
                row = self.highlight_table_word(row, self.highlight, '[cyan]')
            self.table.add_row(*row)
            #console.log(f'Row added {row}')
            row = []

    def generate_table_header(self):
        if self.decimal:
            self.table.add_column('[magenta]Offset(d)[/]', style='red')
            for i in range(self.bytes_per_row):
                self.table.add_column(f'[magenta]{i:02d}[/]')
        else:
            self.table.add_column('[magenta]Offset(h)[/]')
            for i in range(self.bytes_per_row):
                self.table.add_column(f'[magenta]{i:02X}[/]')

    def generate_table_offset(self, counter=int):
        c = '[magenta]'
        if self.decimal:
            offset = f'{c}{counter:08d}:[/]'
        else:
            offset = f'{c}{counter:08X}:[/]'
        return offset
    
    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        cs.console_print.note('loading input file')
        self.load_input_file()
        cs.console_print.note('generating output')
        self.generate_table_output()
        console.print(self.table)
        if self.export != None:
            html_export = console.export_html()
            with open(self.export, 'w', encoding='utf-8') as f:
                f.write(html_export)
            cs.action_save_file2(self.export)
        cs.console_print.ok('Done!')