"""
NRP32 DLL Direct Wrapper

Attempts to call nrp32's rendering functions directly via ctypes.
This bypasses the GUI for maximum speed while using authentic rendering.

Based on reverse engineering of WNrpDll.dll exports:
- CRptDoc::Read(const char* path) - Load .tmp file
- CRptDoc::ShowPage(HDC, page, ...) - Render to device context
- CRptDoc::MakeRtf(const char* path) - Export to RTF
- CRptDoc::MakeTxt(const char* path) - Export to TXT
- CRptDoc::MakeXls(const char* path) - Export to Excel

Note: MakePdf is in nrp32.exe, not the DLL.

Author: Claude Code
"""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path


class NrpDllWrapper:
    """
    Wrapper for WNrpDll.dll functions.

    This provides direct access to nrp32's core rendering functions.
    """

    def __init__(self, dll_path: str = None):
        """
        Initialize the DLL wrapper.

        Args:
            dll_path: Path to WNrpDll.dll
        """
        self.dll_path = dll_path or self._find_dll()
        if not self.dll_path or not os.path.exists(self.dll_path):
            raise FileNotFoundError("WNrpDll.dll not found")

        # Load the DLL
        self.dll = ctypes.CDLL(self.dll_path)
        self._setup_functions()

    def _find_dll(self) -> str:
        """Find WNrpDll.dll"""
        search_paths = [
            Path(__file__).parent.parent.parent / "nrp_backup" / "WNrpDll.dll",
            Path("C:/Program Files/DataWin/WNrpDll.dll"),
        ]
        for p in search_paths:
            if p.exists():
                return str(p)
        return None

    def _setup_functions(self):
        """Setup ctypes function prototypes"""
        # Note: These are C++ mangled names from Borland C++ Builder
        # The actual calling convention and parameters need to be determined
        # through more detailed reverse engineering

        # CRptDoc constructor
        # @CRptDoc@$bctr$qv -> CRptDoc::CRptDoc(void)
        try:
            self._CRptDoc_ctor = self.dll['@CRptDoc@$bctr$qv']
            self._CRptDoc_ctor.restype = ctypes.c_void_p
        except:
            self._CRptDoc_ctor = None

        # CRptDoc::Read
        # @CRptDoc@Read$qpxc -> CRptDoc::Read(const char*)
        try:
            self._CRptDoc_Read = self.dll['@CRptDoc@Read$qpxc']
            self._CRptDoc_Read.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._CRptDoc_Read.restype = ctypes.c_int
        except:
            self._CRptDoc_Read = None

        # CRptDoc::GetPageNum
        # @CRptDoc@GetPageNum$qv -> CRptDoc::GetPageNum(void)
        try:
            self._CRptDoc_GetPageNum = self.dll['@CRptDoc@GetPageNum$qv']
            self._CRptDoc_GetPageNum.argtypes = [ctypes.c_void_p]
            self._CRptDoc_GetPageNum.restype = ctypes.c_int
        except:
            self._CRptDoc_GetPageNum = None

        # CRptDoc::MakeRtf
        try:
            self._CRptDoc_MakeRtf = self.dll['@CRptDoc@MakeRtf$qpc']
            self._CRptDoc_MakeRtf.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._CRptDoc_MakeRtf.restype = ctypes.c_int
        except:
            self._CRptDoc_MakeRtf = None

        # CRptDoc::MakeTxt
        try:
            self._CRptDoc_MakeTxt = self.dll['@CRptDoc@MakeTxt$qpc']
            self._CRptDoc_MakeTxt.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._CRptDoc_MakeTxt.restype = ctypes.c_int
        except:
            self._CRptDoc_MakeTxt = None

    def load_report(self, tmp_path: str) -> bool:
        """
        Load a .tmp report file.

        Args:
            tmp_path: Path to the .tmp file

        Returns:
            True if successful
        """
        if not self._CRptDoc_ctor or not self._CRptDoc_Read:
            raise NotImplementedError("Required DLL functions not found")

        # Create CRptDoc instance
        # Note: This is simplified - actual implementation needs proper
        # C++ object handling
        self.doc = self._CRptDoc_ctor()
        if not self.doc:
            return False

        # Read the file
        path_bytes = tmp_path.encode('mbcs')
        result = self._CRptDoc_Read(self.doc, path_bytes)
        return result != 0

    def get_page_count(self) -> int:
        """Get number of pages in the loaded report"""
        if not self.doc or not self._CRptDoc_GetPageNum:
            return 0
        return self._CRptDoc_GetPageNum(self.doc)

    def export_rtf(self, output_path: str) -> bool:
        """Export to RTF format"""
        if not self.doc or not self._CRptDoc_MakeRtf:
            return False
        path_bytes = output_path.encode('mbcs')
        result = self._CRptDoc_MakeRtf(self.doc, path_bytes)
        return result != 0

    def export_txt(self, output_path: str) -> bool:
        """Export to TXT format"""
        if not self.doc or not self._CRptDoc_MakeTxt:
            return False
        path_bytes = output_path.encode('mbcs')
        result = self._CRptDoc_MakeTxt(self.doc, path_bytes)
        return result != 0


def test_dll():
    """Test the DLL wrapper"""
    print("Testing NRP DLL Wrapper...")
    print()

    try:
        wrapper = NrpDllWrapper()
        print(f"DLL loaded: {wrapper.dll_path}")
        print()

        # List available functions
        print("Available functions:")
        print(f"  CRptDoc constructor: {'Yes' if wrapper._CRptDoc_ctor else 'No'}")
        print(f"  CRptDoc::Read: {'Yes' if wrapper._CRptDoc_Read else 'No'}")
        print(f"  CRptDoc::GetPageNum: {'Yes' if wrapper._CRptDoc_GetPageNum else 'No'}")
        print(f"  CRptDoc::MakeRtf: {'Yes' if wrapper._CRptDoc_MakeRtf else 'No'}")
        print(f"  CRptDoc::MakeTxt: {'Yes' if wrapper._CRptDoc_MakeTxt else 'No'}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_dll()
