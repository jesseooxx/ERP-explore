"""Test ChgPdf.dll directly to create a simple PDF"""
import os
import ctypes
from ctypes import wintypes

os.add_dll_directory('X:/EXE')
os.makedirs('C:/temp', exist_ok=True)

dll_path = 'X:/EXE/'
chgpdf = ctypes.CDLL(dll_path + 'ChgPdf.dll')

# PDF_get_info() -> PDF_info*
# Mangled: ?PDF_get_info@@YAPAUPDF_info@@XZ
# __cdecl (YA), returns pointer (PA) to struct PDF_info (UPDF_info)
PDF_get_info = chgpdf['?PDF_get_info@@YAPAUPDF_info@@XZ']
PDF_get_info.restype = ctypes.c_void_p
PDF_get_info.argtypes = []

# PDF_open(char* filename, PDF_info* info) -> PDF_s*
# Mangled: ?PDF_open@@YGPAUPDF_s@@PADPAUPDF_info@@@Z
# __stdcall (YG), returns PDF_s*, takes char* and PDF_info*
PDF_open = chgpdf['?PDF_open@@YGPAUPDF_s@@PADPAUPDF_info@@@Z']
PDF_open.restype = ctypes.c_void_p
PDF_open.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

# PDF_begin_page(PDF_s* pdf, double width, double height)
PDF_begin_page = chgpdf['?PDF_begin_page@@YAXPAUPDF_s@@NN@Z']
PDF_begin_page.restype = None
PDF_begin_page.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_double]

# PDF_set_font(PDF_s* pdf, char* font, double size, int encoding, bool embed)
PDF_set_font = chgpdf['?PDF_set_font@@YAXPAUPDF_s@@PADNW4PDF_encoding@@_N@Z']
PDF_set_font.restype = None
PDF_set_font.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_double, ctypes.c_int, ctypes.c_bool]

# PDF_show_xy(PDF_s* pdf, char* text, double x, double y)
PDF_show_xy = chgpdf['?PDF_show_xy@@YAXPAUPDF_s@@PADNN@Z']
PDF_show_xy.restype = None
PDF_show_xy.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_double, ctypes.c_double]

# PDF_end_page(PDF_s* pdf)
PDF_end_page = chgpdf['?PDF_end_page@@YAXPAUPDF_s@@@Z']
PDF_end_page.restype = None
PDF_end_page.argtypes = [ctypes.c_void_p]

# PDF_close(PDF_s* pdf)
PDF_close = chgpdf['?PDF_close@@YAXPAUPDF_s@@@Z']
PDF_close.restype = None
PDF_close.argtypes = [ctypes.c_void_p]

print('Testing ChgPdf.dll direct API...')

# Get PDF info structure
info = PDF_get_info()
print(f'PDF_info: {hex(info) if info else "NULL"}')

# Open PDF file
pdf_path = b'C:\\temp\\test_direct.pdf'
pdf = PDF_open(pdf_path, info)
print(f'PDF_open result: {hex(pdf) if pdf else "NULL"}')

if pdf:
    # Begin page (A4 size: 595 x 842 points)
    print('Beginning page...')
    PDF_begin_page(pdf, 595.0, 842.0)

    # Set font
    print('Setting font...')
    try:
        PDF_set_font(pdf, b'Helvetica', 12.0, 0, False)
    except Exception as e:
        print(f'Font error: {e}')

    # Draw text
    print('Drawing text...')
    try:
        PDF_show_xy(pdf, b'Hello from ChgPdf!', 100.0, 700.0)
    except Exception as e:
        print(f'Text error: {e}')

    # End page
    print('Ending page...')
    PDF_end_page(pdf)

    # Close PDF
    print('Closing PDF...')
    PDF_close(pdf)

    # Check result
    if os.path.exists('C:/temp/test_direct.pdf'):
        size = os.path.getsize('C:/temp/test_direct.pdf')
        print(f'SUCCESS! PDF created, size: {size} bytes')
    else:
        print('PDF file not created')
else:
    print('Failed to open PDF')
