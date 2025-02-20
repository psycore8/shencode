from datetime import datetime
import sys
import shutil, fileinput

class helper:
  def GenerateFileName():
    now = datetime.now()
    actDate = now.strftime("%d%m%y-%H%M%S")
    fileName = "sc-" + actDate + ".bin"
    return fileName
    
class bin2sc:
  def process(filename,output):
    sc_output = ""
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
    return sc_output
      
  def process_c(filename):
    shellcode = "\""
    ctr = 1
    maxlen = 15
    for b in open(filename, "rb").read():
      shellcode += "\\x" + b.to_bytes(1, "big").hex()
      if ctr == maxlen:
        shellcode += "\" \n\""
        ctr = 0
      ctr += 1
    shellcode += "\";"
    return shellcode
 
  def process_casm(filename):
    shellcode = "\".byte "
    ctr = 1
    maxlen = 15
    for b in open(filename, "rb").read():
      shellcode += "0x" + b.to_bytes(1, "big").hex()
      if ctr != maxlen:
        shellcode += ","
      if ctr == maxlen:
        shellcode += "\\n\\t\"\n\".byte "
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1] + "\""
    shellcode += "\n\"ret\\n\\t\""
    return shellcode
 
  def process_cs(filename):
    shellcode = ""
    ctr = 1
    maxlen = 15
    for b in open(filename, "rb").read():
      shellcode += "0x" + b.to_bytes(1, "big").hex()
      if ctr != maxlen:
        shellcode += ","
      if ctr == maxlen:
        shellcode += "\n"
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_ps1(filename):
    shellcode = "[Byte[]] $buf = "
    ctr = 1
    maxlen = 15
    for b in open(filename, "rb").read():
      shellcode += "0x" + b.to_bytes(1, "big").hex()
      if ctr != maxlen:
        shellcode += ","
      if ctr == maxlen:
        shellcode += ""
        ctr = 0
      ctr += 1
    shellcode = shellcode[:-1]
    return shellcode

  def process_py(filename):
    shellcode = "buf =  b\'\'\nbuf += b\'\\"
    ctr = 1
    maxlen = 12
    for b in open(filename, "rb").read():
     shellcode += "x" + b.to_bytes(1, "big").hex()
     if ctr != maxlen:
       shellcode += "\\"
     if ctr == maxlen:
       shellcode += "\'\nbuf += b\'\\"
       ctr = 0
     ctr += 1
    shellcode = shellcode[:-1] + "\'"
    return shellcode
 
  def process_hex(filename):
    shellcode = ""
    for b in open(filename, "rb").read():
      shellcode += b.to_bytes(1, "big").hex()
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

