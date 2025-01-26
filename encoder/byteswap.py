import utils.arg
from utils.helper import nstate as nstate
from os import path as osp

class xor:
    Author = 'psycore8'
    Description = 'create payload from a raw file, encode with byteswap-xor, add to byteswap stub'
    Version = '1.0.0'
    Shellcode = ''
    Shellcode_Length = ''
    Modified_Shellcode = b''

    def __init__(self, input_file, output_file, template_file, xor_key):
        self.input_file = input_file
        self.output_file = output_file
        self.template_file = template_file
        self.xor_key = xor_key

    def init():
        spName = 'byteswap'
        spArgList = [
            ['-i', '--input', '', '', 'Input file to use with byteswap stub'],
            ['-o', '--output', '', '', 'outputfile for byteswap stub'],
            ['-k', '--key', '', '', 'the XOR key to use']
        ]
        utils.arg.CreateSubParser(spName, xor.Description, spArgList)

        # spArgList = [
        #     ['-i', '--input', None, None, None, str, True, 'Input file to use with byteswap stub'],
        #     ['-o', '--output', None, None, None, str, True, 'outputfile for byteswap stub'],
        #     ['-k', '--key', None, None, None, int, True, 'the XOR key to use']
        # ]
        # utils.arg.CreateSubParserEx(spName, aes_encoder.Description, spArgList)

    def encrypt(self, data: bytes, xor_key: int) -> bytes:
        transformed = bytearray()
        prev_enc_byte = 0
        for i, byte in enumerate(data):
            if i % 2 == 0: # even byte positions
                enc_byte = byte ^ xor_key
            else:          # odd byte positions
                enc_byte = byte ^ prev_enc_byte
            
            transformed.append(enc_byte)
            prev_enc_byte = enc_byte

        return bytes(transformed)

    def LoadHeader(self):
        try: 
            with open(self.template_file, "rb") as file:
                self.Modified_Shellcode = file.read()
        except FileNotFoundError:
          print(f'{nstate.FAIL} File {self.template_file} not found or cannot be opened.')
          exit()
        size = len(self.Modified_Shellcode)
        print(f'{nstate.OKBLUE} Header loaded, size of shellcode {size} bytes')

    def LoadShellcode(self):
        try:
          with open(self.input_file, 'rb') as file:
             self.Shellcode = file.read()
        except FileNotFoundError:
          print(f'{nstate.FAIL} File {self.input_file} not found or cannot be opened.')
          exit()
        size = len(self.Shellcode)
        self.Shellcode_Length = str(size)
        if size > 255:
           print(f'{nstate.FAIL} Shellcode exceeds max size of 255 bytes')
           exit()
        else:
           print(f'{nstate.INFO} Source Shellcode size {size} bytes')

    def AppendShellcode(self):
        self.Modified_Shellcode += self.encrypt(self.Shellcode, int(self.xor_key))
        size = len(self.Modified_Shellcode)
        print(f'{nstate.OKBLUE} XORed payload added, size of shellcode {size} bytes')

    def replace_bytes_at_offset(self, data, offset, new_bytes):
        data = bytearray(data)
        data[offset] = int(new_bytes.encode('utf-8'))
        data.append(int(new_bytes))
        return bytes(data)

    def WriteToFile(self):
      #outputfile = xor.Output_File
      with open(self.output_file, 'wb') as file:
        file.write(self.Modified_Shellcode)
      path = self.output_file
      cf = osp.isfile(path)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {self.output_file}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
        exit()

    def process(self):
       Length_Offset = 10
       XOR_Key_Offset = 36
       self.LoadHeader()
       self.LoadShellcode()
       self.AppendShellcode()

       self.Modified_Shellcode = self.replace_bytes_at_offset(self.Modified_Shellcode, Length_Offset, self.Shellcode_Length)
       self.Modified_Shellcode = self.replace_bytes_at_offset(self.Modified_Shellcode, XOR_Key_Offset, self.xor_key)
       self.WriteToFile()