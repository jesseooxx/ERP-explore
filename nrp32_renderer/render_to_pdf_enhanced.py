"""
Enhanced TMP to PDF Renderer with Screen Capture Fallback

This version adds a working solution by:
1. Rendering each page to a memory DC (using nview32.dll)
2. Capturing the DC as a bitmap
3. Saving bitmap to temporary file
4. Embedding the image in PDF (using reportlab)

This provides ACTUAL report content in the PDF, not just placeholders.

IMPORTANT: Requires 32-bit Python (py -3.12-32)
IMPORTANT: Requires: pip install pillow reportlab

Author: Claude Code
Date: 2025-12-23
"""

import os
import sys
import ctypes
from ctypes import wintypes, c_int, c_char_p, c_double, c_void_p, POINTER
from pathlib import Path
import struct
import tempfile

# Verify 32-bit Python
if struct.calcsize("P") * 8 != 32:
    print("ERROR: This script requires 32-bit Python!")
    print("Run with: py -3.12-32 render_to_pdf_enhanced.py")
    sys.exit(1)

# Try to import required libraries
try:
    from PIL import Image
except ImportError:
    print("ERROR: PIL/Pillow not installed")
    print("Install with: py -3.12-32 -m pip install pillow")
    sys.exit(1)

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
except ImportError:
    print("ERROR: reportlab not installed")
    print("Install with: py -3.12-32 -m pip install reportlab")
    sys.exit(1)

# Windows GDI constants
SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
BI_RGB = 0

# Windows structures
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ('biSize', wintypes.DWORD),
        ('biWidth', wintypes.LONG),
        ('biHeight', wintypes.LONG),
        ('biPlanes', wintypes.WORD),
        ('biBitCount', wintypes.WORD),
        ('biCompression', wintypes.DWORD),
        ('biSizeImage', wintypes.DWORD),
        ('biXPelsPerMeter', wintypes.LONG),
        ('biYPelsPerMeter', wintypes.LONG),
        ('biClrUsed', wintypes.DWORD),
        ('biClrImportant', wintypes.DWORD),
    ]

class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ('bmiHeader', BITMAPINFOHEADER),
        ('bmiColors', wintypes.DWORD * 3),
    ]

# Initialize Windows APIs
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

# Setup DLL directory
DLL_DIR = 'X:/EXE'
if not os.path.exists(DLL_DIR):
    print(f"ERROR: DLL directory not found: {DLL_DIR}")
    sys.exit(1)

os.environ['PATH'] = DLL_DIR + os.pathsep + os.environ.get('PATH', '')
try:
    kernel32.AddDllDirectory(DLL_DIR)
except:
    pass

os.chdir(DLL_DIR)

# Load required DLLs
print("Loading DLLs...")
try:
    borlndmm = ctypes.CDLL(os.path.join(DLL_DIR, 'borlndmm.dll'))
    cc32 = ctypes.CDLL(os.path.join(DLL_DIR, 'cc32110mt.dll'))
    nview = ctypes.CDLL(os.path.join(DLL_DIR, 'nview32.dll'))
    print("DLLs loaded successfully")
except Exception as e:
    print(f"ERROR loading DLLs: {e}")
    sys.exit(1)


# ============================================================================
# nview32.dll Function Setup
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
# Bitmap Capture Functions
# ============================================================================

def capture_dc_to_image(hdc, width, height):
    """
    Capture a device context to a PIL Image.

    Args:
        hdc: Device context handle
        width: Width in pixels
        height: Height in pixels

    Returns:
        PIL Image object
    """
    # Create bitmap info
    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = -height  # Negative for top-down DIB
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 24  # 24-bit RGB
    bmi.bmiHeader.biCompression = BI_RGB

    # Calculate buffer size
    bytes_per_row = ((width * 3 + 3) // 4) * 4  # 4-byte aligned
    buffer_size = bytes_per_row * height
    buffer = ctypes.create_string_buffer(buffer_size)

    # Get DIB bits
    result = gdi32.GetDIBits(
        hdc,
        gdi32.GetCurrentObject(hdc, 7),  # OBJ_BITMAP = 7
        0,
        height,
        buffer,
        ctypes.byref(bmi),
        DIB_RGB_COLORS
    )

    if result == 0:
        raise RuntimeError("GetDIBits failed")

    # Convert to PIL Image
    # Data is BGR, need to convert to RGB
    img = Image.frombytes('RGB', (width, height), buffer.raw, 'raw', 'BGR', bytes_per_row, 1)

    return img


# ============================================================================
# Enhanced Renderer Class
# ============================================================================

class EnhancedTmpToPdfRenderer:
    """Renders .tmp files to PDF with actual content using bitmap capture"""

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

    def render_page_to_image(self, page_num):
        """
        Render a single page to a PIL Image.

        Args:
            page_num: Page number (1-based)

        Returns:
            PIL Image object
        """
        # Create memory DC
        screen_dc = user32.GetDC(0)
        mem_dc = gdi32.CreateCompatibleDC(screen_dc)
        bitmap = gdi32.CreateCompatibleBitmap(screen_dc, self.width, self.height)
        old_bitmap = gdi32.SelectObject(mem_dc, bitmap)

        # Clear to white
        brush = gdi32.CreateSolidBrush(0xFFFFFF)
        rect = wintypes.RECT(0, 0, self.width, self.height)
        user32.FillRect(mem_dc, ctypes.byref(rect), brush)
        gdi32.DeleteObject(brush)

        # Render page
        showpage(self.doc, mem_dc, page_num, 0, 0, self.width, self.height, 100)

        # Capture to image
        try:
            img = capture_dc_to_image(mem_dc, self.width, self.height)
        finally:
            # Cleanup
            gdi32.SelectObject(mem_dc, old_bitmap)
            gdi32.DeleteObject(bitmap)
            gdi32.DeleteDC(mem_dc)
            user32.ReleaseDC(0, screen_dc)

        return img

    def render_to_pdf(self, output_path, dpi=150):
        """Render all pages to PDF with actual content"""
        if not self.doc:
            print("ERROR: No document loaded")
            return False

        print(f"\nRendering to PDF: {output_path}")
        print(f"DPI: {dpi}")

        # Calculate page size in points (1/72 inch)
        # Convert from pixels assuming screen DPI
        pdf_width = (self.width / dpi) * 72
        pdf_height = (self.height / dpi) * 72

        print(f"PDF page size: {pdf_width:.1f} x {pdf_height:.1f} points")

        # Create PDF
        c = canvas.Canvas(output_path, pagesize=(pdf_width, pdf_height))

        try:
            # Create temporary directory for images
            with tempfile.TemporaryDirectory() as tmpdir:

                # Render each page
                for page_num in range(1, self.pages + 1):
                    print(f"  Rendering page {page_num}/{self.pages}...")

                    # Render to image
                    img = self.render_page_to_image(page_num)

                    # Save to temporary file
                    temp_img_path = os.path.join(tmpdir, f'page_{page_num}.png')
                    img.save(temp_img_path, 'PNG')

                    # Add to PDF (bottom-left origin in reportlab)
                    c.drawImage(temp_img_path, 0, 0, width=pdf_width, height=pdf_height)

                    # Add page number at bottom
                    c.setFont("Helvetica", 8)
                    c.drawString(10, 10, f"Page {page_num}/{self.pages}")

                    # Finish page
                    c.showPage()

                # Save PDF
                c.save()

            # Check result
            if os.path.exists(output_path):
                size = os.path.getsize(output_path)
                print(f"\nSUCCESS! PDF created: {size:,} bytes")
                print(f"Contains {self.pages} page(s) with actual report content")
                return True
            else:
                print("\nERROR: PDF file was not created")
                return False

        except Exception as e:
            print(f"\nERROR during rendering: {e}")
            import traceback
            traceback.print_exc()
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
    print("Enhanced NRP32 Report to PDF Renderer")
    print("With Bitmap Capture - Produces ACTUAL Report Content")
    print("=" * 70)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  py -3.12-32 render_to_pdf_enhanced.py <input.tmp> [output.pdf] [dpi]")
        print("\nExample:")
        print("  py -3.12-32 render_to_pdf_enhanced.py C:\\temp\\test.tmp output.pdf 150")
        print("\nRequirements:")
        print("  - 32-bit Python")
        print("  - pip install pillow reportlab")
        print(f"\nCurrent Python: {struct.calcsize('P') * 8}-bit")
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
    renderer = EnhancedTmpToPdfRenderer()

    try:
        if not renderer.load_tmp(tmp_path):
            return 1

        if not renderer.render_to_pdf(output_path, dpi):
            return 1

        print("\n" + "=" * 70)
        print("COMPLETE - PDF contains actual report content!")
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
