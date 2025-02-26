import ctypes
import ctypes.wintypes

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

EXECUTE_IMMEDIATLY = 0
MEM_COMMIT_RESERVE = 0x00003000
PAGE_READWRITE_EXECUTE = 0x00000040
PROCESS_ALL_ACCESS = 0x1fffff

GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL     = 0x10000000

ACCESS_MASK = ctypes.wintypes.ULONG
BOOL        = ctypes.wintypes.BOOL
DWORD       = ctypes.wintypes.DWORD
HANDLE      = ctypes.wintypes.HANDLE
LONG        = ctypes.wintypes.LONG
LPDWORD     = ctypes.wintypes.LPDWORD
LPVOID      = ctypes.wintypes.LPVOID
LPCVOID     = ctypes.wintypes.LPCVOID
PWORD       = ctypes.wintypes.PWORD
PSIZE_T     = ctypes.wintypes.PSIZE
SIZE_T      = ctypes.c_size_t
ULONG       = ctypes.wintypes.ULONG
VOID        = ctypes.c_void_p

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
CreateRemoteThread.restype = HANDLE

CreateThread = kernel32.CreateThread
CreateThread.argtypes = [LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
CreateThread.restype = HANDLE

HeapAlloc = kernel32.HeapAlloc
HeapAlloc.argtypes = [HANDLE, DWORD, ctypes.c_size_t]
HeapAlloc.restype = LPVOID

HeapCreate = kernel32.HeapCreate
HeapCreate.argtypes = [DWORD, ctypes.c_size_t, ctypes.c_size_t]
HeapCreate.restype = HANDLE

NtCreateThreadEx = ntdll.NtCreateThreadEx
NtCreateThreadEx.argtypes = [ HANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID ]
NtCreateThreadEx.restype = LONG

def pNtCreateThreadEx(
        ThreadHandle=HANDLE, DesiredAccess=ACCESS_MASK, ObjectAttributes: LPVOID=None,
        ProcessHandle=HANDLE, lpStartAddress=LPVOID, lpParameter: LPVOID=None,
        CreateFlags=ULONG, ZeroBits=SIZE_T, SizeOfStackCommit=SIZE_T,
        SizeOfStackReserve=SIZE_T, lpBytesBuffer: LPVOID=None
    ):
    r = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
                         ProcessHandle, lpStartAddress, lpParameter,
                         CreateFlags, ZeroBits, SizeOfStackCommit, 
                         SizeOfStackReserve, lpBytesBuffer)
    return r

NtCreateThread = ntdll.NtCreateThread
NtCreateThread.argtypes = [ HANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID ]
NtCreateThread.restype = LONG

NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
NtWriteVirtualMemory.argtypes = [HANDLE, LPVOID, LPVOID, ULONG, PSIZE_T]
NtWriteVirtualMemory.restype = LONG

def pNtWriteVirtualMemory(
        ProcessHandle=HANDLE, 
        BaseAddress=LPVOID, 
        Buffer=LPVOID, 
        BufferSize=SIZE_T, 
        NumberOfWrittenBytes: HANDLE=None
    ):
    r = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfWrittenBytes)
    return r

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype = HANDLE

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = [HANDLE]
ResumeThread.restype = DWORD

RtlMoveMemory = kernel32.RtlMoveMemory
RtlMoveMemory.argtypes = [LPVOID, LPVOID, SIZE_T]
RtlMoveMemory.restype = None

VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]
VirtualAlloc.restype = LPVOID

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
VirtualAllocEx.restype = LPVOID

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, PWORD]
VirtualProtectEx.restype = BOOL

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [HANDLE, DWORD]
WaitForSingleObject.restype = None

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, SIZE_T, LPVOID]
WriteProcessMemory.restype = BOOL