"""
NView32 DLL Wrapper with __thiscall thunks

Uses machine code thunks to call MSVC __thiscall methods from Python.
"""
import os
import ctypes
from ctypes import c_void_p, c_char_p, c_int, c_double

class NViewWrapper:
    """Wrapper for nview32.dll using thunks for __thiscall convention"""

    def __init__(self, dll_dir=None):
        self.dll_dir = dll_dir or os.path.join(os.path.dirname(__file__), 'dll')

        # Set DLL search path
        os.environ['PATH'] = self.dll_dir + os.pathsep + os.environ.get('PATH', '')
        ctypes.windll.kernel32.SetDllDirectoryW(self.dll_dir)

        # Load dependencies
        for dep in ['borlndmm.dll', 'cc32110mt.dll', 'ChgPdf.dll']:
            try:
                ctypes.CDLL(os.path.join(self.dll_dir, dep))
            except:
                pass

        # Load main DLL
        self.nview = ctypes.CDLL(os.path.join(self.dll_dir, 'nview32.dll'))
        self.kernel32 = ctypes.windll.kernel32

        # Allocate thunk memory
        self._thunk_mem = self.kernel32.VirtualAlloc(None, 512, 0x3000, 0x40)
        self._thunk_offset = 0

        # Setup functions
        self._setup_functions()

        # Document handle
        self._doc = None
        self._heap = self.kernel32.GetProcessHeap()

    def _create_thunk(self, func_addr):
        """Create thunk: pop ret; pop ecx(this); push ret; jmp func"""
        addr = self._thunk_mem + self._thunk_offset
        code = bytearray([0x58, 0x59, 0x50, 0xE9])
        code.extend((func_addr - (addr + 8)).to_bytes(4, 'little', signed=True))
        ctypes.memmove(addr, bytes(code), len(code))
        self._thunk_offset += 16
        return addr

    def _setup_functions(self):
        # Get function addresses
        ctor_addr = ctypes.cast(self.nview['??0CRptDoc@@QAE@XZ'], c_void_p).value
        dtor_addr = ctypes.cast(self.nview['??1CRptDoc@@QAE@XZ'], c_void_p).value
        read_addr = ctypes.cast(self.nview['?Read@CRptDoc@@QAEHPBD@Z'], c_void_p).value
        getpagenum_addr = ctypes.cast(self.nview['?GetPageNum@CRptDoc@@QAEHXZ'], c_void_p).value
        makepdf_addr = ctypes.cast(self.nview['?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z'], c_void_p).value

        # Create thunks and function wrappers
        self._ctor = ctypes.CFUNCTYPE(c_void_p, c_void_p)(self._create_thunk(ctor_addr))
        self._dtor = ctypes.CFUNCTYPE(None, c_void_p)(self._create_thunk(dtor_addr))
        self._read = ctypes.CFUNCTYPE(c_int, c_void_p, c_char_p)(self._create_thunk(read_addr))
        self._getpagenum = ctypes.CFUNCTYPE(c_int, c_void_p)(self._create_thunk(getpagenum_addr))
        self._makepdf = ctypes.CFUNCTYPE(
            c_int, c_void_p, c_char_p,
            c_int, c_int, c_int, c_int, c_int, c_int, c_int, c_int,
            c_double, c_double, c_double
        )(self._create_thunk(makepdf_addr))

    def load(self, tmp_path):
        """Load a TMP report file"""
        if self._doc:
            self.close()

        self._doc = self.kernel32.HeapAlloc(self._heap, 0x08, 16384)
        self._ctor(self._doc)

        path_bytes = os.path.abspath(tmp_path).encode('mbcs')
        result = self._read(self._doc, path_bytes)

        if not result:
            self.close()
            return False
        return True

    def get_page_count(self):
        """Get number of pages"""
        if not self._doc:
            return 0
        return self._getpagenum(self._doc)

    def make_pdf(self, output_path, dpi=300, start_page=1, end_page=0,
                 left=0, right=0, top=0, bottom=0,
                 scale_x=1.0, scale_y=1.0, paper_scale=1.0):
        """Generate PDF"""
        if not self._doc:
            return False

        path_bytes = os.path.abspath(output_path).encode('mbcs')
        result = self._makepdf(
            self._doc, path_bytes,
            dpi, start_page, end_page,
            left, right, top, bottom, 0,  # 8 ints
            scale_x, scale_y, paper_scale
        )
        return result != 0 or os.path.exists(output_path)

    def close(self):
        """Close document"""
        if self._doc:
            self._dtor(self._doc)
            self.kernel32.HeapFree(self._heap, 0, self._doc)
            self._doc = None

    def __del__(self):
        self.close()
        if hasattr(self, '_thunk_mem') and self._thunk_mem:
            self.kernel32.VirtualFree(self._thunk_mem, 0, 0x8000)


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nview_thunk.py <input.tmp> [output.pdf]")
        return

    tmp_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace('.tmp', '.pdf')

    wrapper = NViewWrapper()

    print(f"Loading: {tmp_path}")
    if not wrapper.load(tmp_path):
        print("Failed to load")
        return

    pages = wrapper.get_page_count()
    print(f"Pages: {pages}")

    print(f"Creating: {pdf_path}")
    result = wrapper.make_pdf(pdf_path)
    print(f"MakePdf result: {result}")

    if os.path.exists(pdf_path):
        size = os.path.getsize(pdf_path)
        print(f"SUCCESS! Size: {size:,} bytes")
    else:
        print("PDF not created")

    wrapper.close()


if __name__ == '__main__':
    main()
