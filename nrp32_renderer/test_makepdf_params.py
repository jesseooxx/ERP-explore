"""Test MakePdf with various parameter combinations"""
import os
import ctypes
from ctypes import wintypes

os.add_dll_directory('X:/EXE')
os.chdir('X:/EXE')
os.makedirs('C:/temp', exist_ok=True)

dll_path = 'X:/EXE/'
borlndmm = ctypes.CDLL(dll_path + 'borlndmm.dll')
cc32 = ctypes.CDLL(dll_path + 'cc32110mt.dll')
chgpdf = ctypes.CDLL(dll_path + 'ChgPdf.dll')
nview = ctypes.CDLL(dll_path + 'nview32.dll')

kernel32 = ctypes.windll.kernel32
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

nview_handle = kernel32.GetModuleHandleW('nview32.dll')

# Get functions
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
# 7-int version
makepdf7_addr = GetProcAddress(nview_handle, b'?MakePdf@CRptDoc@@QAEHPADHHHHHHNNN@Z')

# Create thunks
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
thunk_mem = kernel32.VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

def create_thunk(func_addr, offset):
    addr = thunk_mem + offset
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr

ctor_thunk = create_thunk(ctor_addr, 0)
read_thunk = create_thunk(read_addr, 16)
getpagenum_thunk = create_thunk(getpagenum_addr, 32)
makepdf7_thunk = create_thunk(makepdf7_addr, 48)

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
# 7-int version: this, path, i1-i7, d1-d3
MAKEPDF7 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_double, ctypes.c_double, ctypes.c_double)

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)
makepdf7 = MAKEPDF7(makepdf7_thunk)

# Load document
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)
ctor(doc)

result = read(doc, b'C:\\temp\\test.tmp')
print(f'Read result: {result}')

if result != 0:
    pages = getpagenum(doc)
    print(f'Pages: {pages}')

    # Try different parameter combinations
    # Possible meanings: startPage, endPage, width, height, dpi, flags, quality
    test_cases = [
        # (name, i1, i2, i3, i4, i5, i6, i7, d1, d2, d3)
        ('pages_1_4', 1, 4, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0),
        ('pages_0_3', 0, 3, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0),
        ('size_a4', 0, 0, 595, 842, 0, 0, 0, 1.0, 1.0, 1.0),
        ('dpi_300', 0, 0, 0, 0, 300, 0, 0, 1.0, 1.0, 1.0),
        ('flag_1', 0, 0, 0, 0, 0, 1, 0, 1.0, 1.0, 1.0),
        ('all_1', 1, 1, 1, 1, 1, 1, 1, 1.0, 1.0, 1.0),
        ('pages_1_1', 1, 1, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0),  # Just page 1
    ]

    for name, i1, i2, i3, i4, i5, i6, i7, d1, d2, d3 in test_cases:
        pdf_path = f'C:\\temp\\test_{name}.pdf'.encode('ascii')
        result = makepdf7(doc, pdf_path, i1, i2, i3, i4, i5, i6, i7, d1, d2, d3)
        exists = os.path.exists(pdf_path.decode('ascii'))
        size = os.path.getsize(pdf_path.decode('ascii')) if exists else 0
        print(f'{name}: result={result}, exists={exists}, size={size}')

        if result != 0 or size > 0:
            print(f'  *** SUCCESS with params: {i1},{i2},{i3},{i4},{i5},{i6},{i7},{d1},{d2},{d3}')
            break
