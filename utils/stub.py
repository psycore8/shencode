import utils.arg
from os import path as osp

class xor:
    Author = 'psycore8'
    Description = 'create payload from a raw file, encode with xor, add to xor stub'
    Version = '1.0.0'
    Input_File = ''
    Output_File = ''
    Shellcode = ''
    Template_File = ''
    XOR_Key = ''

    def init():
      spName = 'xorstub'
      spArgList = [
        ['-i', '--input', '', '', 'Input file to use with xor stub'],
        ['-o', '--output', '', '', 'outputfile for xor stub'],
        ['-k', '--key', '', '', 'the XOR key to use']
      ]
      utils.arg.CreateSubParser(spName, xor.Description, spArgList)

    def LoadHeader():
        try: 
            with open(xor.Template_File, "rb") as file:
                xor.Shellcode = file.read()
        except FileNotFoundError:
          print(f'[!] File {xor.Template_File} not found or cannot be opened.')
          exit()
        size = len(xor.Shellcode)
        print(f'[+] Header loaded, size of shellcode {size} bytes')

    def AppendShellcode():
        try: 
            with open(xor.Input_File, "rb") as file:
                xor.Shellcode += file.read()
        except FileNotFoundError:
          print(f'[!] File {xor.Input_File} not found or cannot be opened.')
          exit()
        size = len(xor.Shellcode)
        print(f'[+] XORed payload added, size of shellcode {size} bytes')

    def replace_bytes_at_offset(data, offset, new_bytes):
        data = bytearray(data)
        data[offset] = int(new_bytes.encode('UTF-8'))
        data.append(int(new_bytes))
        return bytes(data)

    def WriteToFile():
      outputfile = xor.Output_File
      with open(outputfile, 'wb') as file:
        file.write(xor.Shellcode)
      path = outputfile
      cf = osp.isfile(path)
      if cf == True:
        print(f"[+] XOR encoded shellcode created in {outputfile}")
      else:
        print(f"[!] XOR encoded Shellcode error, aborting script execution")
        exit()

    def process():
       Offset = 5
       xor.LoadHeader()
       xor.AppendShellcode()
       xor.Shellcode = xor.replace_bytes_at_offset(xor.Shellcode, 5, xor.XOR_Key)
       xor.WriteToFile()

    
        