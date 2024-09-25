from datetime import datetime
import sys, utils.arg
import shutil, fileinput

class helper:
  def GenerateFileName():
    now = datetime.now()
    actDate = now.strftime("%d%m%y-%H%M%S")
    fileName = "sc-" + actDate + ".bin"
    return fileName
    
class bin2sc:
  ShowLines = False
  Author = 'psycore8'
  Description = 'create formatted output by filename'
  Version = '1.0.0'

  def init():
    spName = 'formatout'
    spArgList = [
      ['-i', '--input', '', '', 'Input file for formatted output'],
      ['-s', '--syntax', 'c,casm,cs,ps1,py,hex,inspect', '', 'formatting the shellcode in C, Casm, C#, Powershell, python or hex'],
      ['-l', '--lines', '', 'store_true', 'adds a line numbering after each 8 bytes'],
      ['-w', '--write', '', '', 'write output to the given filename (replacing $%BUFFER%$ placeholder in the file']
    ]
    utils.arg.CreateSubParser(spName, bin2sc.Description, spArgList)

  def process(filename,output,lines):
    sc_output = ""
    if lines:
      bin2sc.ShowLines = True
    if output == "c":
      sc_output = bin2sc.process_c(filename)
    if output == "casm":
      sc_output = bin2sc.process_casm(filename)
    if output == "cs":
      sc_output = bin2sc.process_cs(filename)
    if output == "ps1":
      sc_output = bin2sc.process_ps1(filename)
    if output == "py":
      sc_output = bin2sc.process_py(filename)
    if output == "hex":
      sc_output = bin2sc.process_hex(filename)
    if output == "inspect":
      sc_output = bin2sc.process_inspect(filename)
    return sc_output
      
  def ReturnLineNumber(LineFactor, Sum_Output_Bytes, IsFlagSet = False, IsRow1 = False):
    if not IsFlagSet:
      return ''
      exit()
    ValidateLine1 = Sum_Output_Bytes * LineFactor
    if IsRow1:
      LineNumber = '0x00000000: '
    elif ValidateLine1 >= Sum_Output_Bytes:
      Offset = LineFactor * Sum_Output_Bytes
      LineNumber = f'0x{Offset:08}: '
    else:
      print('wrong input')
      exit()
    return LineNumber

  def process_c(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 16
    if bin2sc.ShowLines:
      LineFlag = True
    else:
      LineFlag = False
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}\"'
    for b in open(filename, 'rb').read():
      shellcode += '\\x' + b.to_bytes(1, 'big').hex()
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
        shellcode += f'\" \n{Line_Format}\"'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode += '\";'
    return shellcode
 
  def process_casm(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 16
    if bin2sc.ShowLines:
      LineFlag = True
    else:
      LineFlag = False
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}\".byte '
    for b in open(filename, 'rb').read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
        shellcode += f'\\n\\t\"\n{Line_Format}\".byte '
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1] + '\"'
    shellcode += '\n\"ret\\n\\t\"'
    return shellcode
 
  def process_cs(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 16
    if bin2sc.ShowLines:
      LineFlag = True
    else:
      LineFlag = False
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}'
    for b in open(filename, 'rb').read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
        shellcode += f'\n{Line_Format}'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_ps1(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 16
    #if bin2sc.ShowLines:
      #LineFlag = True
    #else:
    LineFlag = False
    ctr = 1
    maxlen = 16
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}[Byte[]] $buf = '
    for b in open(filename, "rb").read():
      shellcode += '0x' + b.to_bytes(1, 'big').hex()
      if ctr != maxlen:
        shellcode += ','
      if ctr == maxlen:
        Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
        shellcode += f'\n{Line_Format}'
        LineFactor += 1
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_py(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 16
    #if bin2sc.ShowLines:
      #LineFlag = True
    #else:
    LineFlag = False
    ctr = 1
    maxlen = 12
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}buf =  b\'\'\nbuf += b\'\\'
    for b in open(filename, 'rb').read():
     shellcode += 'x' + b.to_bytes(1, 'big').hex()
     if ctr != maxlen:
       shellcode += '\\'
     if ctr == maxlen:
       Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag)
       shellcode += f'\'\n{Line_Format}buf += b\'\\'
       LineFactor += 1
       ctr = 0
     ctr += 1
    shellcode = shellcode[:-1] + '\''
    return shellcode
 
  def process_hex(filename):
    shellcode = ''
    for b in open(filename, 'rb').read():
      shellcode += b.to_bytes(1, 'big').hex()
    return shellcode
  
  def process_inspect(filename):
    retln = bin2sc.ReturnLineNumber
    Sum_Output_Bytes = 8
    #if bin2sc.ShowLines:
    LineFlag = True
    #else:
      #LineFlag = False
    ctr = 1
    maxlen = 8
    LineFactor = 1
    Line_Format = retln(LineFactor, Sum_Output_Bytes, LineFlag, True)
    shellcode = f'{Line_Format}'
    for b in open(filename, 'rb').read():
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
  
class FileManipulation:
  def DuplicateFile(filename):
    dst = 'buf'+filename
    shutil.copyfile(filename, dst)
    return dst
  
  def WriteToTemplate(filename, shellcode):
    TemplateFile = FileManipulation.DuplicateFile(filename)
    TplPlaceholder = '!++BUFFER++!'
    TextReplace = shellcode
    with fileinput.FileInput(TemplateFile, inplace=True) as file:
      for line in file:
        print(line.replace(TplPlaceholder, TextReplace), end='')

