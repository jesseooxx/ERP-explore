"""Test MakePdf using Create instead of/in addition to Read"""
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
user32 = ctypes.windll.user32
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

nview_handle = kernel32.GetModuleHandleW('nview32.dll')

# Get functions (as nrp32.exe imports them)
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
create_addr = GetProcAddress(nview_handle, b'?Create@CRptDoc@@QAEHKHHPBD0@Z')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
getsize_addr = GetProcAddress(nview_handle, b'?GetSize@CRptDoc@@QAEXPAH0@Z')
# 8-int version (what nrp32.exe uses)
makepdf8_addr = GetProcAddress(nview_handle, b'?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z')

print(f'Create: {hex(create_addr)}')
print(f'MakePdf (8 ints): {hex(makepdf8_addr)}')

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
create_thunk_addr = create_thunk(create_addr, 16)
read_thunk = create_thunk(read_addr, 32)
getpagenum_thunk = create_thunk(getpagenum_addr, 48)
getsize_thunk = create_thunk(getsize_addr, 64)
makepdf8_thunk = create_thunk(makepdf8_addr, 80)

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
# Create(ulong, int, int, char*, char*)
CREATE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
GETSIZE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
# 8-int version
MAKEPDF8 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_double, ctypes.c_double, ctypes.c_double)

ctor = CTOR(ctor_thunk)
create = CREATE(create_thunk_addr)
read = READ(read_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)
getsize = GETSIZE(getsize_thunk)
makepdf8 = MAKEPDF8(makepdf8_thunk)

# Load document
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)
ctor(doc)

tmp_path = b'C:\\temp\\test.tmp'

# Method 1: Try Create with various parameters
print('\n=== Testing Create function ===')
test_cases = [
    # (flags, i1, i2, path1, path2)
    (0, 0, 0, tmp_path, None),
    (0, 0, 0, tmp_path, tmp_path),
    (1, 0, 0, tmp_path, None),
    (0, 1, 0, tmp_path, None),
    (0, 0, 1, tmp_path, None),
    (1, 1, 1, tmp_path, tmp_path),
]

for flags, i1, i2, p1, p2 in test_cases:
    # Recreate object
    doc = kernel32.HeapAlloc(heap, 0x08, 16384)
    ctor(doc)

    result = create(doc, flags, i1, i2, p1, p2)
    pages = getpagenum(doc) if result else 0
    print(f'Create({flags},{i1},{i2},{p1 is not None},{p2 is not None}): result={result}, pages={pages}')

    if result != 0 and pages > 0:
        print('  -> Create succeeded!')

        # Try MakePdf
        pdf_path = b'C:\\temp\\test_create.pdf'
        pdf_result = makepdf8(doc, pdf_path, 0, 0, 0, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0)
        if os.path.exists('C:/temp/test_create.pdf'):
            size = os.path.getsize('C:/temp/test_create.pdf')
            print(f'  MakePdf result: {pdf_result}, size: {size}')
            if size > 0:
                print('  *** PDF CREATED SUCCESSFULLY! ***')
                break
        else:
            print(f'  MakePdf result: {pdf_result}, no file')
