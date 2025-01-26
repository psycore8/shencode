import utils.arg
import shutil, fileinput, base64
from utils.helper import nstate as nstate

class format:
  ShowLines = False
  Author = 'psycore8'
  Description = 'create formatted output by filename'
  Version = '1.2.1'
  no_line_break = False

  def __init__(self, input_file, syntax, show_lines, no_break, write_out):
    self.input_file = input_file
    self.syntax = syntax
    self.show_lines = show_lines
    self.no_break = no_break
    self.write_out =write_out
    

  def init():
    spName = 'formatout'
    spArgList = [
      ['-i', '--input', '', '', 'Input file for formatted output'],
      ['-s', '--syntax', 'c,casm,cs,ps1,py,hex,base64,inspect', '', 'formatting the shellcode in C, Casm, C#, Powershell, python or hex'],
      ['-l', '--lines', '', 'store_true', 'adds a line numbering after each 8 bytes'],
      ['-n', '--no-break', '', 'store_true', 'no line break during output'],
      ['-w', '--write', '', '', 'write output to the given filename (replacing $%%BUFFER%%$ placeholder in the file']
    ]
    utils.arg.CreateSubParser(spName, format.Description, spArgList)

   # ['-', '--', None, None, None, None, None, ''],
    # spArgList = [
    #   ['-i', '--input', None, None, None, None, True, 'Input file for formatted output'],
    #   ['-s', '--syntax', ['c','casm','cs','ps1','py','hex','base64','inspect'], None, None, list, True, 'formatting the shellcode in C, Casm, C#, Powershell, python or hex'],
    #   ['-l', '--lines', None, 'store_true', None, None, False, 'adds a line numbering after each 8 bytes'],
    #   ['-n', '--no-break', None, 'store_true', None, None, False, 'no line break during output'],
    #   ['-w', '--write', None, None, None, str, False, 'write output to the given filename (replacing $%%BUFFER%%$ placeholder in the file'],
    # ]
    # utils.arg.CreateSubParserEx(spName, format.Description, spArgList)

  def DuplicateFile(self, filename):
    dst = 'buf'+filename
    shutil.copyfile(filename, dst)
    return dst
  
  def WriteToTemplate(self, filename, shellcode):
    TemplateFile = format.DuplicateFile(filename)
    TplPlaceholder = '!++BUFFER++!'
    TextReplace = shellcode
    with fileinput.FileInput(TemplateFile, inplace=True) as file:
      for line in file:
        print(line.replace(TplPlaceholder, TextReplace), end='')

  def process(self):
    sc_output = ""
    if self.syntax == "c":
      sc_output = self.process_c()
    if self.syntax == "casm":
      sc_output = self.process_casm()
    if self.syntax == "cs":
      sc_output = self.process_cs()
    if self.syntax == "ps1":
      sc_output = self.process_ps1()
    if self.syntax == "py":
      sc_output = self.process_py()
    if self.syntax == "hex":
      sc_output = self.process_hex()
    if self.syntax == "base64":
      sc_output = self.process_base64()
    if self.syntax == "inspect":
      sc_output = self.process_inspect()
    return sc_output
      
  def ReturnLineNumber(self, LineFactor, Sum_Output_Bytes, IsFlagSet = False, IsRow1 = False):
    if not IsFlagSet:
      return ''
      exit()
    ValidateLine1 = Sum_Output_Bytes * LineFactor
    if IsRow1:
      LineNumber = f'{nstate.clGRAY}0x00000000:{nstate.ENDC} '
    elif ValidateLine1 >= Sum_Output_Bytes:
      Offset = LineFactor * Sum_Output_Bytes
      LineNumber = f'{nstate.clGRAY}0x{Offset:08}:{nstate.ENDC} '
    else:
      print('wrong input')
      exit()
    return LineNumber

  def process_c(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 16
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines, True)
    shellcode = f'{Line_Format}\"'
    for b in open(self.input_file, 'rb').read():
      shellcode += '\\x' + b.to_bytes(1, 'big').hex()
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines)
        if self.no_break:
          shellcode += f'{Line_Format}'
        else:
          shellcode += f'\" \n{Line_Format}\"'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode += '\";'
    return shellcode
 
  def process_casm(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 16
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines, True)
    shellcode = f'{Line_Format}\".byte '
    for b in open(self.input_file, 'rb').read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines)
        if self.no_break:
          shellcode += f',{Line_Format}'
        else:
          shellcode += f'\\n\\t\"\n{Line_Format}\".byte '
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1] + '\"'
    shellcode += '\n\"ret\\n\\t\"'
    return shellcode
 
  def process_cs(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 16
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines, True)
    shellcode = f'{Line_Format}'
    for b in open(self.input_file, 'rb').read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines)
        if self.no_break:
          shellcode += f',{Line_Format}'
        else:
          shellcode += f',\n{Line_Format}'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_ps1(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 16
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines, True)
    shellcode = f'{Line_Format}[Byte[]] $buf = '
    for b in open(self.input_file, "rb").read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines)
        if self.no_break:
          shellcode += f',{Line_Format}'
        else:
          shellcode += f',\n{Line_Format}'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_py(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 16
    ctr = 1
    maxlen = 12
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines, True)
    shellcode = f'{Line_Format}buf =  b\'\'\nbuf += b\'\\'
    for b in open(self.input_file, 'rb').read():
     shellcode += 'x' + b.to_bytes(1, 'big').hex()
     if ctr != maxlen:
       shellcode += '\\'
     if ctr == maxlen:
       Line_Format = retln(LineFactor, Sum_Output_Bytes, self.show_lines)
       if self.no_break:
          shellcode += f'\\{Line_Format}'
       else:
          shellcode += f'\'\n{Line_Format}buf += b\'\\'
       LineFactor += 1
       ctr = 0
     ctr += 1
    shellcode = shellcode[:-1] + '\''
    return shellcode
 
  def process_hex(self):
    shellcode = ''
    for b in open(self.input_file, 'rb').read():
      shellcode += b.to_bytes(1, 'big').hex()
    return shellcode
  
  def process_base64(self):
    shellcode = ''
    for b in open(self.input_file, 'rb').read():
      shellcode += b.to_bytes(1, 'big').hex()
    b64_data = base64.b64encode(shellcode.encode('utf-8'))
    return b64_data.decode('utf-8')
  
  def process_inspect(self):
    retln = self.ReturnLineNumber
    Sum_Output_Bytes = 8
    LineFlag = True
    ctr = 1
    maxlen = 8
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}'
    for b in open(self.input_file, 'rb').read():
      shellcode += b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ' '
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
        shellcode += f'\n{Line_Format}'
        LineFactor += 1
        ctr = 0
      ctr += 1
    return shellcode
