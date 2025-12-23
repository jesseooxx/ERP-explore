"""
NRP32 Native DLL Renderer

Directly calls nrp32's WNrpDll.dll to render .tmp files to PDF.
This provides authentic nrp32 rendering at maximum speed.

IMPORTANT: This requires 32-bit Python because WNrpDll.dll is 32-bit.

Usage:
    python nrp32_renderer.py input.tmp output.pdf

Author: Claude Code
"""

import ctypes
from ctypes import wintypes
import os
import sys
import struct
from pathlib import Path
from typing import Optional, Tuple

# Windows GDI constants
HORZRES = 8
VERTRES = 10
LOGPIXELSX = 88
LOGPIXELSY = 90

# GDI functions
gdi32 = ctypes.windll.gdi32
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


class DOCINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.INT),
        ("lpszDocName", wintypes.LPCWSTR),
        ("lpszOutput", wintypes.LPCWSTR),
        ("lpszDatatype", wintypes.LPCWSTR),
        ("fwType", wintypes.DWORD),
    ]


class NrpDllWrapper:
    """
    Wrapper for WNrpDll.dll's CRptDoc class.

    This class handles the complexity of calling Borland C++ methods from Python.
    Borland uses __fastcall convention where 'this' is passed in EAX register.
    """

    def __init__(self, dll_path: str = None):
        """
        Initialize the DLL wrapper.

        Args:
            dll_path: Path to WNrpDll.dll
        """
        # Verify we're running 32-bit Python
        if struct.calcsize("P") * 8 != 32:
            raise RuntimeError(
                "This module requires 32-bit Python to call 32-bit DLL.\n"
                "Install 32-bit Python from: https://www.python.org/downloads/\n"
                "Select 'Windows installer (32-bit)'"
            )

        self.dll_path = dll_path or self._find_dll()
        if not self.dll_path or not os.path.exists(self.dll_path):
            raise FileNotFoundError(f"WNrpDll.dll not found at: {self.dll_path}")

        # Load the DLL
        try:
            self.dll = ctypes.CDLL(self.dll_path)
        except OSError as e:
            raise OSError(f"Failed to load DLL: {e}")

        self._setup_functions()
        self.doc_ptr = None

    def _find_dll(self) -> Optional[str]:
        """Find WNrpDll.dll in common locations"""
        search_paths = [
            Path(__file__).parent.parent / "nrp_backup" / "WNrpDll.dll",
            Path(__file__).parent / "WNrpDll.dll",
            Path("C:/DataWin/WNrpDll.dll"),
            Path("X:/LEILA/NRP32/WNrpDll.dll"),
        ]
        for p in search_paths:
            if p.exists():
                return str(p)
        return None

    def _setup_functions(self):
        """Setup ctypes function prototypes for Borland C++ methods"""

        # Borland C++ name mangling:
        # @ClassName@MethodName$qParameterTypes
        # $q = function, parameter types follow
        # v = void, i = int, pc = char*, pv = void*

        # CRptDoc constructor: CRptDoc::CRptDoc(void)
        # Returns pointer to new CRptDoc object
        try:
            self._ctor = self.dll['@CRptDoc@$bctr$qv']
            # Borland __fastcall: no parameters, returns pointer
            self._ctor.restype = ctypes.c_void_p
            self._ctor.argtypes = []
        except Exception as e:
            print(f"Warning: Constructor not found: {e}")
            self._ctor = None

        # CRptDoc destructor
        try:
            self._dtor = self.dll['@CRptDoc@$bdtr$qv']
            self._dtor.argtypes = [ctypes.c_void_p]  # this pointer
            self._dtor.restype = None
        except:
            self._dtor = None

        # CRptDoc::Read(const char* path)
        try:
            self._read = self.dll['@CRptDoc@Read$qpxc']
            # Borland __fastcall: this in register, path as parameter
            self._read.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._read.restype = ctypes.c_int
        except Exception as e:
            print(f"Warning: Read not found: {e}")
            self._read = None

        # CRptDoc::GetPageNum(void)
        try:
            self._get_page_num = self.dll['@CRptDoc@GetPageNum$qv']
            self._get_page_num.argtypes = [ctypes.c_void_p]
            self._get_page_num.restype = ctypes.c_int
        except:
            self._get_page_num = None

        # CRptDoc::GetSize(int* width, int* height)
        try:
            self._get_size = self.dll['@CRptDoc@GetSize$qpit1']
            self._get_size.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int)
            ]
            self._get_size.restype = None
        except:
            self._get_size = None

        # CRptDoc::ShowPage(HDC hdc, int page, int x, int y, int w, int h, int scale, int flags)
        try:
            self._show_page = self.dll['@CRptDoc@ShowPage$qpviiiiii']
            self._show_page.argtypes = [
                ctypes.c_void_p,  # this
                ctypes.c_void_p,  # HDC
                ctypes.c_int,     # page
                ctypes.c_int,     # x
                ctypes.c_int,     # y
                ctypes.c_int,     # width
                ctypes.c_int,     # height
                ctypes.c_int,     # scale (usually 100)
            ]
            self._show_page.restype = None
        except Exception as e:
            print(f"Warning: ShowPage not found: {e}")
            self._show_page = None

        # CRptDoc::MakeRtf(const char* path)
        try:
            self._make_rtf = self.dll['@CRptDoc@MakeRtf$qpc']
            self._make_rtf.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._make_rtf.restype = ctypes.c_int
        except:
            self._make_rtf = None

        # CRptDoc::MakeTxt(const char* path)
        try:
            self._make_txt = self.dll['@CRptDoc@MakeTxt$qpc']
            self._make_txt.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._make_txt.restype = ctypes.c_int
        except:
            self._make_txt = None

        # CRptDoc::MakeXls(const char* path)
        try:
            self._make_xls = self.dll['@CRptDoc@MakeXls$qpc']
            self._make_xls.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._make_xls.restype = ctypes.c_int
        except:
            self._make_xls = None

    def create_document(self) -> bool:
        """Create a new CRptDoc instance"""
        if not self._ctor:
            raise NotImplementedError("Constructor not available")

        self.doc_ptr = self._ctor()
        return self.doc_ptr is not None

    def load_file(self, tmp_path: str) -> bool:
        """
        Load a .tmp report file.

        Args:
            tmp_path: Path to the .tmp file

        Returns:
            True if successful
        """
        if not self.doc_ptr:
            if not self.create_document():
                return False

        if not self._read:
            raise NotImplementedError("Read function not available")

        # Convert path to bytes (MBCS encoding for Windows)
        path_bytes = os.path.abspath(tmp_path).encode('mbcs')
        result = self._read(self.doc_ptr, path_bytes)
        return result != 0

    def get_page_count(self) -> int:
        """Get the number of pages in the loaded document"""
        if not self.doc_ptr or not self._get_page_num:
            return 0
        return self._get_page_num(self.doc_ptr)

    def get_document_size(self) -> Tuple[int, int]:
        """Get document dimensions (width, height)"""
        if not self.doc_ptr or not self._get_size:
            return (0, 0)

        width = ctypes.c_int()
        height = ctypes.c_int()
        self._get_size(self.doc_ptr, ctypes.byref(width), ctypes.byref(height))
        return (width.value, height.value)

    def render_page_to_dc(self, hdc, page: int, x: int, y: int,
                          width: int, height: int, scale: int = 100):
        """
        Render a page to a device context.

        Args:
            hdc: Windows device context handle
            page: Page number (1-based)
            x, y: Position
            width, height: Render area size
            scale: Scale percentage (100 = 100%)
        """
        if not self.doc_ptr or not self._show_page:
            raise NotImplementedError("ShowPage not available")

        self._show_page(self.doc_ptr, hdc, page, x, y, width, height, scale)

    def export_rtf(self, output_path: str) -> bool:
        """Export document to RTF format"""
        if not self.doc_ptr or not self._make_rtf:
            return False
        path_bytes = os.path.abspath(output_path).encode('mbcs')
        return self._make_rtf(self.doc_ptr, path_bytes) != 0

    def export_txt(self, output_path: str) -> bool:
        """Export document to TXT format"""
        if not self.doc_ptr or not self._make_txt:
            return False
        path_bytes = os.path.abspath(output_path).encode('mbcs')
        return self._make_txt(self.doc_ptr, path_bytes) != 0

    def export_xls(self, output_path: str) -> bool:
        """Export document to XLS format"""
        if not self.doc_ptr or not self._make_xls:
            return False
        path_bytes = os.path.abspath(output_path).encode('mbcs')
        return self._make_xls(self.doc_ptr, path_bytes) != 0

    def close(self):
        """Close the document and free resources"""
        if self.doc_ptr and self._dtor:
            self._dtor(self.doc_ptr)
            self.doc_ptr = None


class PdfPrinter:
    """
    Creates PDF output using Windows GDI printing to a PDF printer.
    """

    def __init__(self, printer_name: str = "Microsoft Print to PDF"):
        self.printer_name = printer_name

    def render_to_pdf(self, wrapper: NrpDllWrapper, output_path: str) -> bool:
        """
        Render the loaded document to PDF using a virtual printer.

        Args:
            wrapper: NrpDllWrapper with loaded document
            output_path: Output PDF path

        Returns:
            True if successful
        """
        try:
            import win32print
            import win32ui
            import win32con
        except ImportError:
            raise ImportError("pywin32 required: pip install pywin32")

        # Get document info
        page_count = wrapper.get_page_count()
        if page_count == 0:
            return False

        doc_width, doc_height = wrapper.get_document_size()

        # Create printer DC
        hprinter = win32print.OpenPrinter(self.printer_name)
        try:
            # Get printer DC
            printer_info = win32print.GetPrinter(hprinter, 2)
            devmode = printer_info['pDevMode']

            # Create DC
            hdc = win32ui.CreateDC()
            hdc.CreatePrinterDC(self.printer_name)

            # Start document
            hdc.StartDoc(output_path)

            # Render each page
            for page in range(1, page_count + 1):
                hdc.StartPage()

                # Get printable area
                print_width = hdc.GetDeviceCaps(HORZRES)
                print_height = hdc.GetDeviceCaps(VERTRES)

                # Render the page
                wrapper.render_page_to_dc(
                    hdc.GetSafeHdc(),
                    page,
                    0, 0,
                    print_width, print_height,
                    100
                )

                hdc.EndPage()

            hdc.EndDoc()
            hdc.DeleteDC()

            return os.path.exists(output_path)

        finally:
            win32print.ClosePrinter(hprinter)


def render_tmp_to_pdf(tmp_path: str, pdf_path: str,
                      dll_path: str = None,
                      printer_name: str = "Microsoft Print to PDF") -> bool:
    """
    Render a .tmp file to PDF using nrp32's native DLL.

    Args:
        tmp_path: Input .tmp file path
        pdf_path: Output PDF path
        dll_path: Path to WNrpDll.dll (optional)
        printer_name: PDF printer name

    Returns:
        True if successful
    """
    wrapper = NrpDllWrapper(dll_path)

    try:
        # Load the document
        if not wrapper.load_file(tmp_path):
            print(f"Failed to load: {tmp_path}")
            return False

        print(f"Loaded: {tmp_path}")
        print(f"Pages: {wrapper.get_page_count()}")
        print(f"Size: {wrapper.get_document_size()}")

        # Render to PDF
        printer = PdfPrinter(printer_name)
        success = printer.render_to_pdf(wrapper, pdf_path)

        if success:
            print(f"Created: {pdf_path}")
        else:
            print("PDF creation failed")

        return success

    finally:
        wrapper.close()


def main():
    """Command line entry point"""
    if len(sys.argv) < 2:
        print("NRP32 Native PDF Renderer")
        print()
        print("Usage:")
        print("  python nrp32_renderer.py <input.tmp> [output.pdf]")
        print()
        print("Options:")
        print("  --info          Show DLL information")
        print("  --rtf <path>    Export to RTF instead of PDF")
        print("  --txt <path>    Export to TXT instead of PDF")
        print()

        # Check if 32-bit
        bits = struct.calcsize("P") * 8
        print(f"Python: {bits}-bit")
        if bits != 32:
            print()
            print("WARNING: This script requires 32-bit Python!")
            print("Install from: https://www.python.org/downloads/")
            print("Select 'Windows installer (32-bit)'")

        sys.exit(1)

    if sys.argv[1] == "--info":
        # Show DLL info
        try:
            wrapper = NrpDllWrapper()
            print(f"DLL: {wrapper.dll_path}")
            print("Available functions:")
            print(f"  Constructor: {'Yes' if wrapper._ctor else 'No'}")
            print(f"  Read: {'Yes' if wrapper._read else 'No'}")
            print(f"  GetPageNum: {'Yes' if wrapper._get_page_num else 'No'}")
            print(f"  GetSize: {'Yes' if wrapper._get_size else 'No'}")
            print(f"  ShowPage: {'Yes' if wrapper._show_page else 'No'}")
            print(f"  MakeRtf: {'Yes' if wrapper._make_rtf else 'No'}")
            print(f"  MakeTxt: {'Yes' if wrapper._make_txt else 'No'}")
            print(f"  MakeXls: {'Yes' if wrapper._make_xls else 'No'}")
        except Exception as e:
            print(f"Error: {e}")
        sys.exit(0)

    # Parse arguments
    tmp_path = sys.argv[1]

    if len(sys.argv) >= 3 and sys.argv[2] == "--rtf":
        # Export to RTF
        output_path = sys.argv[3] if len(sys.argv) > 3 else tmp_path.replace('.tmp', '.rtf')
        wrapper = NrpDllWrapper()
        wrapper.load_file(tmp_path)
        success = wrapper.export_rtf(output_path)
        wrapper.close()
        sys.exit(0 if success else 1)

    elif len(sys.argv) >= 3 and sys.argv[2] == "--txt":
        # Export to TXT
        output_path = sys.argv[3] if len(sys.argv) > 3 else tmp_path.replace('.tmp', '.txt')
        wrapper = NrpDllWrapper()
        wrapper.load_file(tmp_path)
        success = wrapper.export_txt(output_path)
        wrapper.close()
        sys.exit(0 if success else 1)

    else:
        # Default: PDF
        pdf_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace('.tmp', '.pdf').replace('.TMP', '.pdf')
        success = render_tmp_to_pdf(tmp_path, pdf_path)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
