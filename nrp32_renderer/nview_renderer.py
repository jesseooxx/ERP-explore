"""
NView32 Direct PDF Renderer

Uses nview32.dll's MakePdf function to generate PDFs directly.
This provides the fastest possible PDF generation using the native engine.

nview32.dll exports (MSVC name mangling):
- ?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z
  = int CRptDoc::MakePdf(char* path, int, int, int, int, int, int, int, double, double, double)

IMPORTANT: Requires 32-bit Python because nview32.dll is 32-bit.

Author: Claude Code
"""

import ctypes
from ctypes import wintypes, c_int, c_char_p, c_double, c_void_p, POINTER
import os
import sys
import struct
from pathlib import Path
from typing import Optional


class NViewRenderer:
    """
    Direct PDF renderer using nview32.dll.

    This calls the CRptDoc::MakePdf function directly for
    maximum speed and perfect output fidelity.
    """

    def __init__(self, dll_dir: str = None):
        """
        Initialize the renderer.

        Args:
            dll_dir: Directory containing nview32.dll and dependencies
        """
        # Verify 32-bit Python
        if struct.calcsize("P") * 8 != 32:
            raise RuntimeError(
                "This module requires 32-bit Python.\n"
                "Install from: https://www.python.org/downloads/\n"
                "Select 'Windows installer (32-bit)'"
            )

        self.dll_dir = dll_dir or self._find_dll_dir()
        if not self.dll_dir:
            raise FileNotFoundError("DLL directory not found")

        # Add DLL directory to path for dependency loading
        os.environ['PATH'] = self.dll_dir + os.pathsep + os.environ.get('PATH', '')

        # Also use AddDllDirectory on Windows
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.AddDllDirectory(self.dll_dir)
        except:
            pass

        # Load nview32.dll
        nview_path = os.path.join(self.dll_dir, 'nview32.dll')
        if not os.path.exists(nview_path):
            raise FileNotFoundError(f"nview32.dll not found at {nview_path}")

        try:
            self.nview = ctypes.CDLL(nview_path)
        except OSError as e:
            raise OSError(f"Failed to load nview32.dll: {e}")

        self._setup_functions()
        self.doc = None

    def _find_dll_dir(self) -> Optional[str]:
        """Find the DLL directory"""
        paths = [
            Path(__file__).parent / "dll",
            Path(__file__).parent,
            Path("C:/DataWin/exe"),
        ]
        for p in paths:
            if (p / "nview32.dll").exists():
                return str(p)
        return None

    def _setup_functions(self):
        """Setup ctypes function prototypes"""

        # MSVC name mangling for CRptDoc methods
        # ??0CRptDoc@@QAE@XZ = CRptDoc::CRptDoc() constructor
        # ??1CRptDoc@@QAE@XZ = CRptDoc::~CRptDoc() destructor

        # Constructor: CRptDoc::CRptDoc()
        try:
            self._ctor = self.nview['??0CRptDoc@@QAE@XZ']
            # MSVC thiscall: this pointer passed in ECX
            # We need to handle this specially
            self._ctor.restype = c_void_p
            self._ctor.argtypes = [c_void_p]  # this pointer
        except Exception as e:
            print(f"Constructor not found: {e}")
            self._ctor = None

        # Destructor
        try:
            self._dtor = self.nview['??1CRptDoc@@QAE@XZ']
            self._dtor.argtypes = [c_void_p]
            self._dtor.restype = None
        except:
            self._dtor = None

        # CRptDoc::Read(const char* path)
        # ?Read@CRptDoc@@QAEHPBD@Z = int Read(const char*)
        try:
            self._read = self.nview['?Read@CRptDoc@@QAEHPBD@Z']
            self._read.argtypes = [c_void_p, c_char_p]
            self._read.restype = c_int
        except Exception as e:
            print(f"Read not found: {e}")
            self._read = None

        # CRptDoc::GetPageNum()
        # ?GetPageNum@CRptDoc@@QAEHXZ = int GetPageNum()
        try:
            self._get_page_num = self.nview['?GetPageNum@CRptDoc@@QAEHXZ']
            self._get_page_num.argtypes = [c_void_p]
            self._get_page_num.restype = c_int
        except:
            self._get_page_num = None

        # CRptDoc::MakePdf
        # ?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z
        # int MakePdf(char* path, int, int, int, int, int, int, int, double, double, double)
        try:
            self._make_pdf = self.nview['?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z']
            self._make_pdf.argtypes = [
                c_void_p,    # this
                c_char_p,    # output path
                c_int,       # dpi?
                c_int,       # start page?
                c_int,       # end page?
                c_int,       # left margin?
                c_int,       # right margin?
                c_int,       # top margin?
                c_int,       # bottom margin?
                c_double,    # scale X?
                c_double,    # scale Y?
                c_double,    # paper scale?
            ]
            self._make_pdf.restype = c_int
        except Exception as e:
            print(f"MakePdf not found: {e}")
            self._make_pdf = None

    def _alloc_object(self) -> c_void_p:
        """Allocate memory for CRptDoc object"""
        # CRptDoc object size is unknown, use a generous estimate
        # Typically C++ objects are a few hundred bytes
        size = 4096  # Should be more than enough
        buffer = ctypes.create_string_buffer(size)
        return ctypes.cast(buffer, c_void_p)

    def load_file(self, tmp_path: str) -> bool:
        """
        Load a .tmp report file.

        Args:
            tmp_path: Path to the .tmp file

        Returns:
            True if successful
        """
        if not self._read:
            raise NotImplementedError("Read function not available")

        # Allocate CRptDoc object
        self.doc = self._alloc_object()

        # Call constructor
        if self._ctor:
            self._ctor(self.doc)

        # Call Read
        path_bytes = os.path.abspath(tmp_path).encode('mbcs')
        result = self._read(self.doc, path_bytes)
        return result != 0

    def get_page_count(self) -> int:
        """Get number of pages"""
        if not self.doc or not self._get_page_num:
            return 0
        return self._get_page_num(self.doc)

    def make_pdf(self, output_path: str, dpi: int = 300) -> bool:
        """
        Generate PDF from loaded document.

        Args:
            output_path: Output PDF path
            dpi: Resolution (default 300)

        Returns:
            True if successful
        """
        if not self.doc:
            raise RuntimeError("No document loaded")
        if not self._make_pdf:
            raise NotImplementedError("MakePdf not available")

        path_bytes = os.path.abspath(output_path).encode('mbcs')

        # Call MakePdf
        # Parameters based on reverse engineering:
        # path, dpi, startPage, endPage, leftMargin, rightMargin, topMargin, bottomMargin, scaleX, scaleY, paperScale
        result = self._make_pdf(
            self.doc,
            path_bytes,
            dpi,      # DPI
            1,        # Start page
            0,        # End page (0 = all)
            0,        # Left margin
            0,        # Right margin
            0,        # Top margin
            0,        # Bottom margin
            1.0,      # Scale X
            1.0,      # Scale Y
            1.0,      # Paper scale
        )

        return result != 0 and os.path.exists(output_path)

    def close(self):
        """Close document and free resources"""
        if self.doc and self._dtor:
            self._dtor(self.doc)
            self.doc = None


def render_to_pdf(tmp_path: str, pdf_path: str, dll_dir: str = None) -> bool:
    """
    Render a .tmp file to PDF using nview32.dll.

    Args:
        tmp_path: Input .tmp file
        pdf_path: Output PDF path
        dll_dir: Directory containing DLLs

    Returns:
        True if successful
    """
    renderer = NViewRenderer(dll_dir)

    try:
        print(f"Loading: {tmp_path}")
        if not renderer.load_file(tmp_path):
            print("Failed to load file")
            return False

        pages = renderer.get_page_count()
        print(f"Pages: {pages}")

        print(f"Generating PDF: {pdf_path}")
        if renderer.make_pdf(pdf_path):
            size = os.path.getsize(pdf_path)
            print(f"Success! Size: {size:,} bytes")
            return True
        else:
            print("PDF generation failed")
            return False

    finally:
        renderer.close()


def main():
    """Command line interface"""
    import sys

    if len(sys.argv) < 2:
        print("NView32 Direct PDF Renderer")
        print()
        print("Usage: python nview_renderer.py <input.tmp> [output.pdf]")
        print()

        # Check architecture
        bits = struct.calcsize("P") * 8
        print(f"Python: {bits}-bit")
        if bits != 32:
            print()
            print("ERROR: Requires 32-bit Python!")
            print("Install from: https://www.python.org/downloads/")

        sys.exit(1)

    tmp_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace('.tmp', '.pdf').replace('.TMP', '.pdf')

    success = render_to_pdf(tmp_path, pdf_path)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
