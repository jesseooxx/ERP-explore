"""Test MakePdf with X:/EXE as working directory"""
import os
import ctypes
from ctypes import wintypes

# Add X:\EXE to DLL search path
os.add_dll_directory('X:/EXE')

# Switch to X:\EXE (read-only access)
os.chdir('X:/EXE')
print(f'Working directory: {os.getcwd()}')

# Ensure output directory exists
os.makedirs('C:/temp', exist_ok=True)

# Load DLLs with full path
print('Loading DLLs...')
dll_path = 'X:/EXE/'
borlndmm = ctypes.CDLL(dll_path + 'borlndmm.dll')
cc32 = ctypes.CDLL(dll_path + 'cc32110mt.dll')
chgpdf = ctypes.CDLL(dll_path + 'ChgPdf.dll')
nview = ctypes.CDLL(dll_path + 'nview32.dll')
print('DLLs loaded successfully')

# Get function addresses
kernel32 = ctypes.windll.kernel32
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

nview_handle = kernel32.GetModuleHandleW('nview32.dll')
print(f'nview32 handle: {hex(nview_handle)}')

# Get key functions
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
makepdf_addr = GetProcAddress(nview_handle, b'?MakePdf@CRptDoc@@QAEHPADHHHHHHNNN@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
print(f'Constructor: {hex(ctor_addr)}')
print(f'Read: {hex(read_addr)}')
print(f'MakePdf: {hex(makepdf_addr)}')
print(f'GetPageNum: {hex(getpagenum_addr)}')

# Create thunk memory
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
thunk_mem = kernel32.VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
print(f'Thunk memory: {hex(thunk_mem)}')

def create_thunk(func_addr, offset):
    addr = thunk_mem + offset
    # pop eax; pop ecx; push eax; jmp rel32
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr

ctor_thunk = create_thunk(ctor_addr, 0)
read_thunk = create_thunk(read_addr, 16)
makepdf_thunk = create_thunk(makepdf_addr, 32)
getpagenum_thunk = create_thunk(getpagenum_addr, 48)

# Define function types
CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
MAKEPDF = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p,
                           ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                           ctypes.c_int, ctypes.c_int, ctypes.c_double, ctypes.c_double, ctypes.c_double)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
makepdf = MAKEPDF(makepdf_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)

# Allocate object memory
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)  # HEAP_ZERO_MEMORY
print(f'CRptDoc object: {hex(doc)}')

# Construct object
print('Calling constructor...')
ctor(doc)
print('Constructor OK')

# Read test file
tmp_file = b'C:\\temp\\test.tmp'
print(f'Reading: {tmp_file}')
result = read(doc, tmp_file)
print(f'Read result: {result}')

if result != 0:
    # Get page count
    pages = getpagenum(doc)
    print(f'Page count: {pages}')

    # Try MakePdf
    pdf_path = b'C:\\temp\\test_from_xexe.pdf'
    print(f'Calling MakePdf: {pdf_path}')
    # MakePdf(path, ?, ?, ?, ?, ?, ?, scale1, scale2, scale3)
    result = makepdf(doc, pdf_path, 0, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0)
    print(f'MakePdf result: {result}')

    # Check if file was created
    if os.path.exists('C:/temp/test_from_xexe.pdf'):
        size = os.path.getsize('C:/temp/test_from_xexe.pdf')
        print(f'PDF created! Size: {size} bytes')
    else:
        print('PDF not created')
else:
    print('Read failed - checking if test.tmp exists...')
    if os.path.exists('C:/temp/test.tmp'):
        print(f'test.tmp exists, size: {os.path.getsize("C:/temp/test.tmp")}')
    else:
        print('test.tmp does not exist')
