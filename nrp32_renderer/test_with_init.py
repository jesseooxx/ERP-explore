"""Test MakePdf with Initial() call"""
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

# Get functions
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
initial_addr = GetProcAddress(nview_handle, b'?Initial@CRptDoc@@IAEXXZ')
startdoc_addr = GetProcAddress(nview_handle, b'?StartDocA@CRptDoc@@QAEHXZ')
create_addr = GetProcAddress(nview_handle, b'?Create@CRptDoc@@QAEHKHHPBD0@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
makepdf_hwnd_addr = GetProcAddress(nview_handle, b'?MakePdf@CRptDoc@@QAEHPADPAUHWND__@@HHHHHHNNN@Z')

print(f'Initial: {hex(initial_addr) if initial_addr else "NOT FOUND"}')
print(f'StartDocA: {hex(startdoc_addr) if startdoc_addr else "NOT FOUND"}')
print(f'Create: {hex(create_addr) if create_addr else "NOT FOUND"}')
print(f'MakePdf (with HWND): {hex(makepdf_hwnd_addr) if makepdf_hwnd_addr else "NOT FOUND"}')

# Create thunks
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
thunk_mem = kernel32.VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

def create_thunk(func_addr, offset):
    if not func_addr:
        return None
    addr = thunk_mem + offset
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr

ctor_thunk = create_thunk(ctor_addr, 0)
read_thunk = create_thunk(read_addr, 16)
initial_thunk = create_thunk(initial_addr, 32)
startdoc_thunk = create_thunk(startdoc_addr, 48)
getpagenum_thunk = create_thunk(getpagenum_addr, 64)
makepdf_hwnd_thunk = create_thunk(makepdf_hwnd_addr, 80)

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
INITIAL = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
STARTDOC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
# MakePdf with HWND: path, hwnd, i1-i7, d1-d3
MAKEPDF_HWND = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
                                 ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_double, ctypes.c_double, ctypes.c_double)

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
initial = INITIAL(initial_thunk) if initial_thunk else None
startdoc = STARTDOC(startdoc_thunk) if startdoc_thunk else None
getpagenum = GETPAGENUM(getpagenum_thunk)
makepdf_hwnd = MAKEPDF_HWND(makepdf_hwnd_thunk) if makepdf_hwnd_thunk else None

# Create a hidden window for HWND
WS_OVERLAPPEDWINDOW = 0x00CF0000
SW_HIDE = 0

hwnd = user32.CreateWindowExW(
    0, 'STATIC', 'PDFTest', WS_OVERLAPPEDWINDOW,
    0, 0, 100, 100, 0, 0, 0, 0
)
print(f'Created HWND: {hex(hwnd) if hwnd else "NULL"}')

# Load document
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)
ctor(doc)

print('\nCalling Initial...')
if initial:
    initial(doc)
    print('Initial OK')

result = read(doc, b'C:\\temp\\test.tmp')
print(f'Read result: {result}')

if result != 0:
    pages = getpagenum(doc)
    print(f'Pages: {pages}')

    if startdoc:
        print('Calling StartDocA...')
        sd_result = startdoc(doc)
        print(f'StartDocA result: {sd_result}')

    if makepdf_hwnd:
        pdf_path = b'C:\\temp\\test_with_hwnd.pdf'
        print(f'Calling MakePdf with HWND...')
        result = makepdf_hwnd(doc, pdf_path, hwnd, 1, 4, 0, 0, 0, 0, 0, 1.0, 1.0, 1.0)
        print(f'MakePdf result: {result}')

        if os.path.exists('C:/temp/test_with_hwnd.pdf'):
            size = os.path.getsize('C:/temp/test_with_hwnd.pdf')
            print(f'PDF created! Size: {size} bytes')
        else:
            print('PDF not created')

# Clean up
if hwnd:
    user32.DestroyWindow(hwnd)
