"""Test AddToPdf with FILE* handle"""
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

# Get C runtime for FILE* operations
msvcrt = ctypes.CDLL('msvcrt.dll')

kernel32 = ctypes.windll.kernel32
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

nview_handle = kernel32.GetModuleHandleW('nview32.dll')

# Get functions
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
addtopdf_addr = GetProcAddress(nview_handle, b'?AddToPdf@CRptDoc@@QAEXPAU_iobuf@@@Z')
getsize_addr = GetProcAddress(nview_handle, b'?GetSize@CRptDoc@@QAEXPAH0@Z')

print(f'AddToPdf: {hex(addtopdf_addr)}')
print(f'GetSize: {hex(getsize_addr) if getsize_addr else "NOT FOUND"}')

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
addtopdf_thunk = create_thunk(addtopdf_addr, 48)
getsize_thunk = create_thunk(getsize_addr, 64) if getsize_addr else None

CTOR = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
GETPAGENUM = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
ADDTOPDF = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)  # returns void, takes FILE*
GETSIZE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))

ctor = CTOR(ctor_thunk)
read = READ(read_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)
addtopdf = ADDTOPDF(addtopdf_thunk)
getsize = GETSIZE(getsize_thunk) if getsize_thunk else None

# Load document
heap = kernel32.GetProcessHeap()
doc = kernel32.HeapAlloc(heap, 0x08, 16384)
ctor(doc)

result = read(doc, b'C:\\temp\\test.tmp')
print(f'Read result: {result}')

if result != 0:
    pages = getpagenum(doc)
    print(f'Pages: {pages}')

    if getsize:
        w = ctypes.c_int(0)
        h = ctypes.c_int(0)
        getsize(doc, ctypes.byref(w), ctypes.byref(h))
        print(f'Size: {w.value} x {h.value}')

    # Open a file with msvcrt fopen
    msvcrt.fopen.restype = ctypes.c_void_p
    msvcrt.fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    msvcrt.fclose.argtypes = [ctypes.c_void_p]

    print('\nOpening PDF file...')
    pdf_file = msvcrt.fopen(b'C:\\temp\\test_addto.pdf', b'wb')
    print(f'FILE*: {hex(pdf_file) if pdf_file else "NULL"}')

    if pdf_file:
        print('Calling AddToPdf...')
        try:
            addtopdf(doc, pdf_file)
            print('AddToPdf completed')
        except Exception as e:
            print(f'AddToPdf error: {e}')

        msvcrt.fclose(pdf_file)

        if os.path.exists('C:/temp/test_addto.pdf'):
            size = os.path.getsize('C:/temp/test_addto.pdf')
            print(f'File created, size: {size} bytes')
        else:
            print('File not created')
