"""Test MakePdf with 8 int parameters version"""
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
# 8-int version
makepdf8_addr = GetProcAddress(nview_handle, b'?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z')

print(f'MakePdf (8 ints): {hex(makepdf8_addr)}')

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
makepdf8_thunk = create_thunk(makepdf8_addr, 32)

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
# 8-int version: path, i1-i8, d1-d3
MAKEPDF8 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_double, ctypes.c_double, ctypes.c_double)

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
makepdf8 = MAKEPDF8(makepdf8_thunk)

heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)

ctor(doc)
result = read(doc, b'C:\\temp\\test.tmp')
print(f'Read result: {result}')

if result != 0:
    pdf_path = b'C:\\temp\\test_8int.pdf'
    print('Trying MakePdf with 8 int params...')
    result = makepdf8(doc, pdf_path, 0, 0, 0, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0)
    print(f'MakePdf (8 ints, all 0): {result}')

    if os.path.exists('C:/temp/test_8int.pdf'):
        print(f'PDF created! Size: {os.path.getsize("C:/temp/test_8int.pdf")}')
    else:
        # Try with 1s
        result = makepdf8(doc, b'C:\\temp\\test_8int_v2.pdf', 1, 1, 1, 1, 1, 1, 1, 1, 1.0, 1.0, 1.0)
        print(f'MakePdf (8 ints, all 1): {result}')
        if os.path.exists('C:/temp/test_8int_v2.pdf'):
            print(f'PDF v2 created! Size: {os.path.getsize("C:/temp/test_8int_v2.pdf")}')
        else:
            print('Both attempts failed')
