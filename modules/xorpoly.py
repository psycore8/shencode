from utils.helper import nstate as nstate
from os import path as osp

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR stub')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR stub')
    parser.add_argument('-k', '--key', help='Key for XOR stub')

class xor:
    Author = 'psycore8'
    Description = 'create payload from a raw file, encode with xor, add to xor stub'
    Version = '2.0.0'

    def __init__(self, input_file, output_file, shellcode, xored_shellcode, template_file, xor_key):
       self.input_file = input_file
       self.output_file = output_file
       self.shellcode = shellcode
       self.xored_shellcode = xored_shellcode
       self.template_file = template_file
       self.xor_key = xor_key

    def LoadHeader(self):
        try: 
            with open(self.template_file, "rb") as file:
                self.shellcode = file.read()
        except FileNotFoundError:
          print(f'{nstate.FAIL} File {self.template_file} not found or cannot be opened.')
          exit()
        size = len(self.shellcode)
        print(f'{nstate.OKBLUE} Header loaded, size of shellcode {size} bytes')

    def AppendShellcode(self):
        self.shellcode += self.xored_shellcode
        size = len(self.shellcode)
        print(f'{nstate.OKBLUE} XORed payload added, size of shellcode {size} bytes')

    def replace_bytes_at_offset(data, offset, new_bytes):
        data = bytearray(data)
        data[offset] = int(new_bytes.encode('UTF-8'))
        data.append(int(new_bytes))
        return bytes(data)

    def WriteToFile(self):
      outputfile = self.output_file #xor.Output_File
      with open(outputfile, 'wb') as file:
        file.write(self.shellcode)
      path = outputfile
      cf = osp.isfile(path)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {outputfile}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
        exit()

    def process(self):
       #Offset = 5
       xor.LoadHeader(self)
       xor.AppendShellcode(self)
       self.shellcode = xor.replace_bytes_at_offset(self.shellcode, 5, self.xor_key)
       xor.WriteToFile(self)

    
        