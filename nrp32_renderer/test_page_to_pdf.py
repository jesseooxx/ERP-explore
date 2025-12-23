"""Test rendering report pages to PDF using lower-level functions"""
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

# Get CRptDoc functions
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
getsize_addr = GetProcAddress(nview_handle, b'?GetSize@CRptDoc@@QAEXAAH0@Z')
pagetopdf_addr = GetProcAddress(nview_handle, b'?PageToPdf@CRptDoc@@QAEHH@Z')

print(f'PageToPdf: {hex(pagetopdf_addr) if pagetopdf_addr else "NOT FOUND"}')

# Also check for functions that set up PDF output
setpdf_addr = GetProcAddress(nview_handle, b'?SetPdf@CRptDoc@@QAEXPAX@Z')
startpdf_addr = GetProcAddress(nview_handle, b'?StartPdf@CRptDoc@@QAEHXZ')
print(f'SetPdf: {hex(setpdf_addr) if setpdf_addr else "NOT FOUND"}')
print(f'StartPdf: {hex(startpdf_addr) if startpdf_addr else "NOT FOUND"}')

# Check all PDF-related exports
import pefile
pe = pefile.PE('X:/EXE/nview32.dll')
print('\nAll PDF-related exports:')
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        name = exp.name.decode('ascii', errors='ignore')
        if 'Pdf' in name or 'pdf' in name or 'PDF' in name:
            addr = GetProcAddress(nview_handle, exp.name)
            print(f'  {name}: {hex(addr)}')

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
getsize_thunk = create_thunk(getsize_addr, 48)
pagetopdf_thunk = create_thunk(pagetopdf_addr, 64) if pagetopdf_addr else None

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
GETSIZE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
PAGETOPDF = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)
getsize = GETSIZE(getsize_thunk)
pagetopdf = PAGETOPDF(pagetopdf_thunk) if pagetopdf_thunk else None

# Load document
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)
ctor(doc)

result = read(doc, b'C:\\temp\\test.tmp')
print(f'\nRead result: {result}')

if result != 0:
    pages = getpagenum(doc)
    print(f'Pages: {pages}')

    w = ctypes.c_int(0)
    h = ctypes.c_int(0)
    getsize(doc, ctypes.byref(w), ctypes.byref(h))
    print(f'Size: {w.value} x {h.value}')

    if pagetopdf:
        print('\nTrying PageToPdf for page 1...')
        result = pagetopdf(doc, 1)
        print(f'PageToPdf result: {result}')
