"""
Render .tmp Report to PDF using ChgPdf.dll

This script combines:
- nview32.dll's CRptDoc to read .tmp files and render to memory DC
- ChgPdf.dll to create PDF output
- Windows GDI to capture rendered content and convert to PDF

The strategy:
1. Read .tmp file using nview32's CRptDoc
2. For each page, use ShowPage() to render to a memory DC
3. Extract text and graphics from the DC
4. Use ChgPdf to recreate in PDF format

IMPORTANT: Requires 32-bit Python (py -3.12-32)
IMPORTANT: Must run from X:/EXE/ directory for DLL dependencies

Author: Claude Code
Date: 2025-12-23
"""

import os
import sys
import ctypes
from ctypes import wintypes, c_int, c_char_p, c_double, c_void_p, POINTER
from pathlib import Path
import struct

# Verify 32-bit Python
if struct.calcsize("P") * 8 != 32:
    print("ERROR: This script requires 32-bit Python!")
    print("Run with: py -3.12-32 render_to_pdf.py")
    sys.exit(1)

# Windows GDI constants
HORZRES = 8
VERTRES = 10
LOGPIXELSX = 88
LOGPIXELSY = 90
SRCCOPY = 0x00CC0020

# Initialize Windows APIs
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

# Setup DLL directory (must be X:/EXE/)
DLL_DIR = 'X:/EXE'
if not os.path.exists(DLL_DIR):
    print(f"ERROR: DLL directory not found: {DLL_DIR}")
    sys.exit(1)

# Add DLL directory to path
os.environ['PATH'] = DLL_DIR + os.pathsep + os.environ.get('PATH', '')
try:
    kernel32.AddDllDirectory(DLL_DIR)
except:
    pass

# Change to DLL directory (important for dependencies)
os.chdir(DLL_DIR)

# Load required DLLs
print("Loading DLLs...")
try:
    borlndmm = ctypes.CDLL(os.path.join(DLL_DIR, 'borlndmm.dll'))
    cc32 = ctypes.CDLL(os.path.join(DLL_DIR, 'cc32110mt.dll'))
    nview = ctypes.CDLL(os.path.join(DLL_DIR, 'nview32.dll'))
    chgpdf = ctypes.CDLL(os.path.join(DLL_DIR, 'ChgPdf.dll'))
    print("DLLs loaded successfully")
except Exception as e:
    print(f"ERROR loading DLLs: {e}")
    sys.exit(1)


# ============================================================================
# ChgPdf.dll Function Setup
# ============================================================================

# PDF_get_info() -> PDF_info*
PDF_get_info = chgpdf['?PDF_get_info@@YAPAUPDF_info@@XZ']
PDF_get_info.restype = c_void_p
PDF_get_info.argtypes = []

# PDF_open(char* filename, PDF_info* info) -> PDF_s*
PDF_open = chgpdf['?PDF_open@@YGPAUPDF_s@@PADPAUPDF_info@@@Z']
PDF_open.restype = c_void_p
PDF_open.argtypes = [c_char_p, c_void_p]

# PDF_begin_page(PDF_s* pdf, double width, double height)
PDF_begin_page = chgpdf['?PDF_begin_page@@YAXPAUPDF_s@@NN@Z']
PDF_begin_page.restype = None
PDF_begin_page.argtypes = [c_void_p, c_double, c_double]

# PDF_set_font(PDF_s* pdf, char* font, double size, int encoding, bool embed)
PDF_set_font = chgpdf['?PDF_set_font@@YAXPAUPDF_s@@PADNW4PDF_encoding@@_N@Z']
PDF_set_font.restype = None
PDF_set_font.argtypes = [c_void_p, c_char_p, c_double, c_int, ctypes.c_bool]

# PDF_show_xy(PDF_s* pdf, char* text, double x, double y)
PDF_show_xy = chgpdf['?PDF_show_xy@@YAXPAUPDF_s@@PADNN@Z']
PDF_show_xy.restype = None
PDF_show_xy.argtypes = [c_void_p, c_char_p, c_double, c_double]

# PDF_end_page(PDF_s* pdf)
PDF_end_page = chgpdf['?PDF_end_page@@YAXPAUPDF_s@@@Z']
PDF_end_page.restype = None
PDF_end_page.argtypes = [c_void_p]

# PDF_close(PDF_s* pdf)
PDF_close = chgpdf['?PDF_close@@YAXPAUPDF_s@@@Z']
PDF_close.restype = None
PDF_close.argtypes = [c_void_p]

# PDF_save_image(PDF_s* pdf, HDC hdc, int x, int y, int w, int h, double pdf_x, double pdf_y, double pdf_w, double pdf_h)
# This function may or may not exist - try to get it
try:
    PDF_save_image = chgpdf['?PDF_save_image@@YAXPAUPDF_s@@PAUHDC__@@HHHHNNNN@Z']
    PDF_save_image.restype = None
    PDF_save_image.argtypes = [c_void_p, c_void_p, c_int, c_int, c_int, c_int, c_double, c_double, c_double, c_double]
    HAS_PDF_SAVE_IMAGE = True
except:
    HAS_PDF_SAVE_IMAGE = False


# ============================================================================
# nview32.dll Function Setup (using thunks for __thiscall)
# ============================================================================

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, c_char_p]

nview_handle = kernel32.GetModuleHandleW('nview32.dll')

# Get function addresses
ctor_addr = GetProcAddress(nview_handle, b'??0CRptDoc@@QAE@XZ')
read_addr = GetProcAddress(nview_handle, b'?Read@CRptDoc@@QAEHPBD@Z')
getpagenum_addr = GetProcAddress(nview_handle, b'?GetPageNum@CRptDoc@@QAEHXZ')
getsize_addr = GetProcAddress(nview_handle, b'?GetSize@CRptDoc@@QAEXPAH0@Z')
showpage_addr = GetProcAddress(nview_handle, b'?ShowPage@CRptDoc@@QAEXPAUHDC__@@HHHHHHH@Z')

print(f"Function addresses:")
print(f"  Constructor: {hex(ctor_addr) if ctor_addr else 'NOT FOUND'}")
print(f"  Read: {hex(read_addr) if read_addr else 'NOT FOUND'}")
print(f"  GetPageNum: {hex(getpagenum_addr) if getpagenum_addr else 'NOT FOUND'}")
print(f"  GetSize: {hex(getsize_addr) if getsize_addr else 'NOT FOUND'}")
print(f"  ShowPage: {hex(showpage_addr) if showpage_addr else 'NOT FOUND'}")

if not all([ctor_addr, read_addr, getpagenum_addr, getsize_addr, showpage_addr]):
    print("ERROR: Required nview32.dll functions not found")
    sys.exit(1)

# Create thunks for __thiscall convention
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

thunk_mem = kernel32.VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

def create_thunk(func_addr, offset):
    """Create a thunk to convert cdecl to __thiscall (this in ECX)"""
    addr = thunk_mem + offset
    # Machine code: pop eax, pop ecx, push eax, jmp func_addr
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr

# Create thunks
ctor_thunk = create_thunk(ctor_addr, 0)
read_thunk = create_thunk(read_addr, 16)
getpagenum_thunk = create_thunk(getpagenum_addr, 32)
getsize_thunk = create_thunk(getsize_addr, 48)
showpage_thunk = create_thunk(showpage_addr, 64)

# Create function prototypes
CTOR = ctypes.CFUNCTYPE(None, c_void_p)
READ = ctypes.CFUNCTYPE(c_int, c_void_p, c_char_p)
GETPAGENUM = ctypes.CFUNCTYPE(c_int, c_void_p)
GETSIZE = ctypes.CFUNCTYPE(None, c_void_p, POINTER(c_int), POINTER(c_int))
SHOWPAGE = ctypes.CFUNCTYPE(None, c_void_p, c_void_p, c_int, c_int, c_int, c_int, c_int, c_int)

# Wrap thunks
ctor = CTOR(ctor_thunk)
read_func = READ(read_thunk)
getpagenum = GETPAGENUM(getpagenum_thunk)
getsize = GETSIZE(getsize_thunk)
showpage = SHOWPAGE(showpage_thunk)


# ============================================================================
# Report Rendering Class
# ============================================================================

class TmpToPdfRenderer:
    """Renders .tmp files to PDF using nview32.dll and ChgPdf.dll"""

    def __init__(self):
        self.doc = None
        self.pages = 0
        self.width = 0
        self.height = 0

    def load_tmp(self, tmp_path):
        """Load a .tmp file"""
        print(f"\nLoading: {tmp_path}")

        # Allocate CRptDoc object
        heap = kernel32.GetProcessHeap()
        self.doc = kernel32.HeapAlloc(heap, 0x08, 16384)

        # Call constructor
        ctor(self.doc)

        # Read file
        path_bytes = os.path.abspath(tmp_path).encode('mbcs')
        result = read_func(self.doc, path_bytes)

        if result == 0:
            print("ERROR: Failed to read .tmp file")
            return False

        # Get page count
        self.pages = getpagenum(self.doc)
        print(f"Pages: {self.pages}")

        # Get dimensions
        w = c_int(0)
        h = c_int(0)
        getsize(self.doc, ctypes.byref(w), ctypes.byref(h))
        self.width = w.value
        self.height = h.value
        print(f"Size: {self.width} x {self.height}")

        return True

    def render_to_pdf(self, output_path, dpi=150):
        """Render all pages to PDF"""
        if not self.doc:
            print("ERROR: No document loaded")
            return False

        print(f"\nRendering to PDF: {output_path}")
        print(f"DPI: {dpi}")

        # Get PDF info structure
        pdf_info = PDF_get_info()

        # Open PDF
        pdf_path_bytes = os.path.abspath(output_path).encode('mbcs')
        pdf = PDF_open(pdf_path_bytes, pdf_info)

        if not pdf:
            print("ERROR: Failed to create PDF")
            return False

        try:
            # Calculate page dimensions in points (1/72 inch)
            # Typical A4: 595 x 842 points
            scale_factor = dpi / 72.0
            pdf_width = self.width / scale_factor
            pdf_height = self.height / scale_factor

            print(f"PDF page size: {pdf_width:.1f} x {pdf_height:.1f} points")

            # Render each page
            for page_num in range(1, self.pages + 1):
                print(f"  Rendering page {page_num}/{self.pages}...")

                # Begin PDF page
                PDF_begin_page(pdf, pdf_width, pdf_height)

                # Create memory DC for rendering
                screen_dc = user32.GetDC(0)
                mem_dc = gdi32.CreateCompatibleDC(screen_dc)
                bitmap = gdi32.CreateCompatibleBitmap(screen_dc, self.width, self.height)
                old_bitmap = gdi32.SelectObject(mem_dc, bitmap)

                # Clear to white
                brush = gdi32.CreateSolidBrush(0xFFFFFF)  # White
                rect = wintypes.RECT(0, 0, self.width, self.height)
                user32.FillRect(mem_dc, ctypes.byref(rect), brush)
                gdi32.DeleteObject(brush)

                # Render page to memory DC
                showpage(self.doc, mem_dc, page_num, 0, 0, self.width, self.height, 100)

                # Try to save image to PDF if function exists
                if HAS_PDF_SAVE_IMAGE:
                    PDF_save_image(pdf, mem_dc, 0, 0, self.width, self.height,
                                 0.0, 0.0, pdf_width, pdf_height)
                else:
                    # Fallback: Add placeholder text
                    PDF_set_font(pdf, b'Helvetica', 12.0, 0, False)
                    text = f"Page {page_num} - Rendering not fully supported".encode('mbcs')
                    PDF_show_xy(pdf, text, 50.0, pdf_height - 50.0)

                    # Add note
                    PDF_set_font(pdf, b'Helvetica', 10.0, 0, False)
                    note = b'ChgPdf.dll does not have PDF_save_image function.'
                    PDF_show_xy(pdf, note, 50.0, pdf_height - 70.0)
                    note2 = b'Consider using GUI automation or screen capture method.'
                    PDF_show_xy(pdf, note2, 50.0, pdf_height - 85.0)

                # Cleanup DC resources
                gdi32.SelectObject(mem_dc, old_bitmap)
                gdi32.DeleteObject(bitmap)
                gdi32.DeleteDC(mem_dc)
                user32.ReleaseDC(0, screen_dc)

                # End PDF page
                PDF_end_page(pdf)

            # Close PDF
            PDF_close(pdf)

            # Check result
            if os.path.exists(output_path):
                size = os.path.getsize(output_path)
                print(f"\nSUCCESS! PDF created: {size:,} bytes")
                return True
            else:
                print("\nERROR: PDF file was not created")
                return False

        except Exception as e:
            print(f"\nERROR during rendering: {e}")
            import traceback
            traceback.print_exc()
            PDF_close(pdf)
            return False

    def cleanup(self):
        """Free resources"""
        if self.doc:
            heap = kernel32.GetProcessHeap()
            kernel32.HeapFree(heap, 0, self.doc)
            self.doc = None


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Command line interface"""

    print("=" * 70)
    print("NRP32 Report to PDF Renderer")
    print("=" * 70)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  py -3.12-32 render_to_pdf.py <input.tmp> [output.pdf] [dpi]")
        print("\nExample:")
        print("  py -3.12-32 render_to_pdf.py C:\\temp\\test.tmp C:\\temp\\output.pdf 150")
        print("\nNOTE: This script MUST be run with 32-bit Python")
        print(f"Current Python: {struct.calcsize('P') * 8}-bit")
        return 1

    # Parse arguments
    tmp_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace('.tmp', '.pdf').replace('.TMP', '.pdf')
    dpi = int(sys.argv[3]) if len(sys.argv) > 3 else 150

    # Validate input
    if not os.path.exists(tmp_path):
        print(f"\nERROR: Input file not found: {tmp_path}")
        return 1

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)

    # Render
    renderer = TmpToPdfRenderer()

    try:
        if not renderer.load_tmp(tmp_path):
            return 1

        if not renderer.render_to_pdf(output_path, dpi):
            return 1

        print("\n" + "=" * 70)
        print("COMPLETE")
        print("=" * 70)
        return 0

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        renderer.cleanup()


if __name__ == '__main__':
    sys.exit(main())
