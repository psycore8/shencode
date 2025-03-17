import ctypes
import ctypes.wintypes

kernel32     = ctypes.windll.kernel32
ntdll        = ctypes.windll.ntdll
user32       = ctypes.windll.user32

# EXECUTE_IMMEDIATLY = 0
# MEM_COMMIT_RESERVE = 0x00003000
# NT_SUCCESS = 0
# PAGE_READWRITE_EXECUTE = 0x00000040
# PROCESS_ALL_ACCESS = 0x1fffff
# PROCESS_CREATE_FLAGS_SUSPENDED = 0x00000200
# THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001

# GENERIC_READ    = 0x80000000
# GENERIC_WRITE   = 0x40000000
# GENERIC_EXECUTE = 0x20000000
# GENERIC_ALL     = 0x10000000

# # Define MemoryProtections
# PAGE_EXECUTE_READWRITE = 0x00000040
# PAGE_EXECUTE_READ =      0x00000020
# PAGE_READWRITE =         0x00000004
# PAGE_READONLY =          0x00000002
# PAGE_SIZE =              0x00001000

ACCESS_MASK = ctypes.wintypes.ULONG
BOOL        = ctypes.wintypes.BOOL
BYTE        = ctypes.wintypes.BYTE
DWORD       = ctypes.wintypes.DWORD
HANDLE      = ctypes.wintypes.HANDLE
HMODULE     = ctypes.wintypes.HMODULE
LARGE_INT   = ctypes.wintypes.LARGE_INTEGER
LONG        = ctypes.wintypes.LONG
LPDWORD     = ctypes.wintypes.LPDWORD
LPVOID      = ctypes.wintypes.LPVOID
LPCSTR      = ctypes.wintypes.LPCSTR
LPCVOID     = ctypes.wintypes.LPCVOID
LPCWSTR     = ctypes.wintypes.LPCWSTR
LPWSTR      = ctypes.wintypes.LPWSTR
PWORD       = ctypes.wintypes.PWORD
PSIZE_T     = ctypes.wintypes.PSIZE
PULONG      = ctypes.wintypes.PULONG
SIZE_T      = ctypes.c_size_t
ULONG       = ctypes.wintypes.ULONG
USHORT      = ctypes.wintypes.USHORT
ULONG_PTR   = ctypes.POINTER(SIZE_T)
VOID        = ctypes.c_void_p
WORD        = ctypes.wintypes.WORD

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
CreateRemoteThread.restype = HANDLE

CreateThread = kernel32.CreateThread
CreateThread.argtypes = [LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
CreateThread.restype = HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [ HANDLE, LPCSTR ]
GetProcAddress.restype = LPVOID

ZwUnmapViewOfSection = ntdll.ZwUnmapViewOfSection
ZwUnmapViewOfSection.argtypes = [ HANDLE, LPVOID ]
ZwUnmapViewOfSection.restype = LONG

# Process-Overwriting

CreateProcess = kernel32.CreateProcessW
GetThreadContext = kernel32.GetThreadContext
SetThreadContext = kernel32.SetThreadContext

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", DWORD),
                ("lpReserved", LPWSTR),
                ("lpDesktop", LPWSTR),
                ("lpTitle", LPWSTR),
                ("dwX", DWORD),
                ("dwY", DWORD),
                ("dwXSize", DWORD),
                ("dwYSize", DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags", DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]
    
class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong),
        ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort),
        ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort),
        ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),  # Instruktionszeiger für 64-Bit
    ]
    
NtCreateSection = ntdll.NtCreateSection
NtCreateSection.argtypes = (ctypes.POINTER(HANDLE), DWORD, LPVOID,
                            ctypes.POINTER(LARGE_INT), DWORD, DWORD, HANDLE)
NtCreateSection.restype = LONG

def pNtCreateSection(
        SectionHandle           = HANDLE,
        DesiredAccess           = ACCESS_MASK,
        ObjectAttributes        = LPVOID,
        MaimumSize              = LARGE_INT,
        SectionPageProtection   = DWORD,
        AllocationAttributes    = DWORD,
        FileHandle              = HANDLE
):
    r = NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaimumSize, SectionPageProtection, AllocationAttributes, FileHandle)
    return r

EnumWindows = user32.EnumWindows
EnumWindows.argtypes = [ LPVOID, LPVOID ]
EnumWindows.restype = BOOL

def pEnumWindows(lpEnumFunc=LPVOID, lParam=LPVOID):
    r = EnumWindows(lpEnumFunc, lParam)
    return r

HeapAlloc = kernel32.HeapAlloc
HeapAlloc.argtypes = [HANDLE, DWORD, ctypes.c_size_t]
HeapAlloc.restype = LPVOID

HeapCreate = kernel32.HeapCreate
HeapCreate.argtypes = [DWORD, ctypes.c_size_t, ctypes.c_size_t]
HeapCreate.restype = HANDLE

LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.argtypes = [ LPCSTR ]
LoadLibraryA.restype = HMODULE

def pLoadLibraryA(lpLibFileName: LPCSTR):
    r = LoadLibraryA(lpLibFileName)
    return r

LoadLibraryW = kernel32.LoadLibraryW
LoadLibraryW.argtypes = [ LPCSTR ]
LoadLibraryW.restype = HMODULE

NtAllocateVirtualMemory = ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = [ HANDLE, LPVOID, ULONG, ULONG_PTR, ULONG, ULONG ]
NtAllocateVirtualMemory.restype = LONG

def pNtAllocateVirtualMemory(
        ProcessHandle=HANDLE, BaseAddress=LPVOID, ZeroBits=ULONG,
        RegionSize=ULONG_PTR, AllocationType=ULONG, Protect=ULONG
    ):
    r = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
    return r

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

# NtCreateThread = ntdll.NtCreateThread
# NtCreateThread.argtypes = [ HANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID ]
# NtCreateThread.restype = LONG

NtResumeThread = ntdll.NtResumeThread
NtResumeThread.argtypes = [ HANDLE, PULONG ]
NtResumeThread.restype = LONG

def pNtResumeThread(ThreadHandle=HANDLE, PreviousSuspendCount=PULONG):
    r = NtResumeThread(ThreadHandle, PreviousSuspendCount)
    return r

NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
NtWriteVirtualMemory.argtypes = [HANDLE, LPVOID, LPVOID, ULONG, PSIZE_T]
NtWriteVirtualMemory.restype = LONG

def pNtWriteVirtualMemory(
        ProcessHandle=HANDLE, BaseAddress=LPVOID, Buffer=LPVOID,
        BufferSize=SIZE_T, NumberOfBytesWritten: PSIZE_T=None
    ):
    r = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten)
    return r

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