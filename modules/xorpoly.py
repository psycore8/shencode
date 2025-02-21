from utils.helper import nstate as nstate
from utils.helper import CheckFile, GetFileInfo
from os import path as osp
from modules.xor import xor_encoder

CATEGORY = 'encoder'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for XOR stub')
    parser.add_argument('-o', '--output', help= 'Outputfile for XOR stub')
    parser.add_argument('-k', '--key', type=int, help='Key for XOR stub')

class xor:
    Author = 'psycore8'
    Description = 'create payload from a raw file, encode with xor, add to xor stub'
    Version = '2.1.0'
    DisplayName = 'X0RP0LY-ENC'
    data_size = 0
    hash = ''

    def __init__(self, input_file, output_file, shellcode, xored_shellcode, template_file, xor_key):
       self.input_file = input_file
       self.output_file = output_file
       self.shellcode = shellcode
       self.xored_shellcode = xored_shellcode
       self.template_file = template_file
       self.xor_key = xor_key
       with open(self.input_file, 'rb') as file:
          self.shellcode = file.read()

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'error.template' : f'{nstate.s_fail} File {self.template_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded!\n{nstate.s_note} Size of shellcode {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created!\n{nstate.s_note} Size {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.stub_ok'   : f'{nstate.s_ok} Stub {self.template_file} loaded!\n{nstate.s_note} Size {self.data_size} bytes\n{nstate.s_note} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.output_try': f'{nstate.s_note} Try to write XORPOLY shellcode to file',
            'proc.stub'      : f'{nstate.s_note} Try to load stub from {self.template_file}',
            'proc.try'       : f'{nstate.s_note} Try to append shellcode',
            'proc.key'       : f'{nstate.s_note} Changing key to {self.xor_key}',
            'proc.stats'     : f'{nstate.s_note} Shellcode size: {len(self.shellcode)} bytes'
            #'proc.verbose'   : f'\n{self.out}\n'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def LoadHeader(self):
        #try: 
        with open(self.template_file, "rb") as file:
            self.shellcode = file.read()
        #except FileNotFoundError:
         # print(f'{nstate.FAIL} File {self.template_file} not found or cannot be opened.')
        #  exit()
        #size = len(self.shellcode)
        #print(f'{nstate.OKBLUE} Header loaded, size of shellcode {size} bytes')

    def AppendShellcode(self):
        self.shellcode += self.xored_shellcode
        #size = len(self.shellcode)
        #print(f'{nstate.OKBLUE} XORed payload added, size of shellcode {size} bytes')

    def replace_bytes_at_offset(data, offset, new_bytes):
        data = bytearray(data)
        data[offset] = new_bytes
        data.append(int(new_bytes))
        return bytes(data)

    def WriteToFile(self):
      outputfile = self.output_file #xor.Output_File
      with open(outputfile, 'wb') as file:
        file.write(self.shellcode)
      # path = outputfile
      # cf = osp.isfile(path)
      # if cf == True:
      #   print(f"{nstate.OKGREEN} XOR encoded shellcode created in {outputfile}")
      # else:
      #   print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
      #   exit()

    def process(self):
        #Offset = 5
        self.msg('pre.head')
        xor_enc = xor_encoder('', '', 0, False)
        self.xored_shellcode = xor_enc.xor_crypt_bytes(self.shellcode, self.xor_key)
        self.msg('proc.stub')
        if CheckFile(self.template_file):
          self.data_size, self.hash = GetFileInfo(self.template_file)
          xor.LoadHeader(self)
          self.msg('proc.stub_ok')
          self.msg('proc.stats')
        else:
            self.msg('error.template', True)
        self.msg('proc.try')
        if CheckFile(self.input_file):
           self.data_size, self.hash = GetFileInfo(self.input_file)
           self.msg('proc.input_ok')
           xor.AppendShellcode(self)
           self.msg('proc.stats')
           self.msg('proc.key')
           self.shellcode = xor.replace_bytes_at_offset(self.shellcode, 5, self.xor_key)
        else:
           self.msg('error.input', True)
        self.msg('proc.output_try')
        xor.WriteToFile(self)
        if CheckFile(self.output_file):
           self.data_size, self.hash = GetFileInfo(self.output_file)
           self.msg('proc.output_ok')
        else:
           self.msg('error.output', True)
        self.msg('post.done')

    
        