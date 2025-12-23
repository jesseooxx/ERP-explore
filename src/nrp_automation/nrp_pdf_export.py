"""
NRP32 PDF Export Automation

Uses Windows GUI automation to control nrp32.exe for PDF generation.
This preserves the exact nrp32 rendering while automating the export process.

Requirements:
    pip install pywinauto pyautogui

Usage:
    python nrp_pdf_export.py input.tmp output.pdf

Author: Claude Code
"""

import subprocess
import time
import os
import sys
from pathlib import Path

try:
    import pyautogui
    HAS_PYAUTOGUI = True
except ImportError:
    HAS_PYAUTOGUI = False

try:
    from pywinauto import Application, Desktop
    from pywinauto.keyboard import send_keys
    HAS_PYWINAUTO = True
except ImportError:
    HAS_PYWINAUTO = False


class NrpPdfExporter:
    """Automates nrp32.exe to export PDF files"""

    def __init__(self, nrp_path: str = None):
        """
        Initialize the exporter.

        Args:
            nrp_path: Path to nrp32.exe. If None, searches common locations.
        """
        self.nrp_path = nrp_path or self._find_nrp32()
        if not self.nrp_path or not os.path.exists(self.nrp_path):
            raise FileNotFoundError("nrp32.exe not found")

    def _find_nrp32(self) -> str:
        """Find nrp32.exe in common locations"""
        search_paths = [
            Path(__file__).parent.parent.parent / "nrp_backup" / "nrp32.exe",
            Path("C:/Program Files/DataWin/nrp32.exe"),
            Path("C:/DataWin/nrp32.exe"),
            Path("X:/LEILA/NRP32/nrp32.exe"),
        ]
        for p in search_paths:
            if p.exists():
                return str(p)
        return None

    def export_pdf(self, tmp_path: str, pdf_path: str, timeout: int = 30) -> bool:
        """
        Export a .tmp file to PDF using nrp32.

        Args:
            tmp_path: Path to the .tmp file
            pdf_path: Output PDF path
            timeout: Maximum wait time in seconds

        Returns:
            True if successful, False otherwise
        """
        tmp_path = os.path.abspath(tmp_path)
        pdf_path = os.path.abspath(pdf_path)

        if not os.path.exists(tmp_path):
            raise FileNotFoundError(f"TMP file not found: {tmp_path}")

        # Ensure output directory exists
        os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

        if HAS_PYWINAUTO:
            return self._export_with_pywinauto(tmp_path, pdf_path, timeout)
        elif HAS_PYAUTOGUI:
            return self._export_with_pyautogui(tmp_path, pdf_path, timeout)
        else:
            raise ImportError("Please install pywinauto or pyautogui: pip install pywinauto")

    def _export_with_pywinauto(self, tmp_path: str, pdf_path: str, timeout: int) -> bool:
        """Export using pywinauto for precise control"""
        try:
            # Start nrp32 with the tmp file
            app = Application(backend="win32").start(
                f'"{self.nrp_path}" "{tmp_path}"',
                timeout=10
            )

            # Wait for main window
            time.sleep(1)

            # Find the main window (DataWin Report Viewer)
            main_window = None
            for _ in range(10):
                try:
                    main_window = app.window(title_re=".*Report.*|.*NRP.*|.*DataWin.*")
                    if main_window.exists():
                        break
                except:
                    pass
                time.sleep(0.5)

            if not main_window or not main_window.exists():
                print("Warning: Could not find main window, trying keyboard shortcuts...")

            # Use keyboard shortcut to open PDF export
            # Common shortcuts: Ctrl+P for print, or menu File > Export > PDF
            time.sleep(0.5)

            # Try Alt+F to open File menu
            send_keys('%f')  # Alt+F
            time.sleep(0.3)

            # Look for Export or PDF option
            send_keys('x')  # Export (assuming 'x' is the hotkey)
            time.sleep(0.3)

            send_keys('p')  # PDF
            time.sleep(0.5)

            # In the save dialog, type the output path
            send_keys(pdf_path, with_spaces=True)
            time.sleep(0.3)

            # Press Enter to save
            send_keys('{ENTER}')
            time.sleep(1)

            # Wait for PDF to be created
            start_time = time.time()
            while time.time() - start_time < timeout:
                if os.path.exists(pdf_path):
                    # Give it a moment to finish writing
                    time.sleep(0.5)
                    break
                time.sleep(0.5)

            # Close the application
            try:
                send_keys('%{F4}')  # Alt+F4
                time.sleep(0.5)
            except:
                pass

            app.kill()

            return os.path.exists(pdf_path)

        except Exception as e:
            print(f"Error during export: {e}")
            # Try to kill any remaining nrp32 processes
            os.system('taskkill /f /im nrp32.exe 2>nul')
            return False

    def _export_with_pyautogui(self, tmp_path: str, pdf_path: str, timeout: int) -> bool:
        """Export using pyautogui (simpler but less precise)"""
        try:
            # Start nrp32
            proc = subprocess.Popen([self.nrp_path, tmp_path])
            time.sleep(2)  # Wait for window to open

            # Use keyboard shortcuts
            pyautogui.hotkey('alt', 'f')  # Open File menu
            time.sleep(0.3)
            pyautogui.press('x')  # Export
            time.sleep(0.3)
            pyautogui.press('p')  # PDF
            time.sleep(0.5)

            # Type output path
            pyautogui.typewrite(pdf_path, interval=0.02)
            time.sleep(0.3)
            pyautogui.press('enter')
            time.sleep(1)

            # Wait for file
            start_time = time.time()
            while time.time() - start_time < timeout:
                if os.path.exists(pdf_path):
                    time.sleep(0.5)
                    break
                time.sleep(0.5)

            # Close
            pyautogui.hotkey('alt', 'F4')
            time.sleep(0.5)
            proc.terminate()

            return os.path.exists(pdf_path)

        except Exception as e:
            print(f"Error: {e}")
            os.system('taskkill /f /im nrp32.exe 2>nul')
            return False


def batch_export(tmp_files: list, output_dir: str, nrp_path: str = None) -> dict:
    """
    Batch export multiple .tmp files to PDF.

    This is more efficient than individual exports because it keeps
    nrp32 running between files.

    Args:
        tmp_files: List of .tmp file paths
        output_dir: Directory for output PDFs
        nrp_path: Path to nrp32.exe

    Returns:
        Dict mapping input files to output files (or None if failed)
    """
    exporter = NrpPdfExporter(nrp_path)
    results = {}

    os.makedirs(output_dir, exist_ok=True)

    for tmp_file in tmp_files:
        tmp_path = Path(tmp_file)
        pdf_name = tmp_path.stem + ".pdf"
        pdf_path = os.path.join(output_dir, pdf_name)

        print(f"Exporting: {tmp_file} -> {pdf_path}")
        success = exporter.export_pdf(tmp_file, pdf_path)

        if success:
            results[tmp_file] = pdf_path
            print(f"  Success!")
        else:
            results[tmp_file] = None
            print(f"  Failed!")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nrp_pdf_export.py <input.tmp> [output.pdf]")
        print("       python nrp_pdf_export.py --batch <dir_with_tmp_files> <output_dir>")
        sys.exit(1)

    if sys.argv[1] == "--batch":
        if len(sys.argv) < 4:
            print("Usage: python nrp_pdf_export.py --batch <input_dir> <output_dir>")
            sys.exit(1)

        input_dir = sys.argv[2]
        output_dir = sys.argv[3]

        tmp_files = list(Path(input_dir).glob("*.tmp")) + list(Path(input_dir).glob("*.TMP"))
        results = batch_export([str(f) for f in tmp_files], output_dir)

        success = sum(1 for v in results.values() if v)
        print(f"\nCompleted: {success}/{len(results)} successful")

    else:
        tmp_path = sys.argv[1]
        pdf_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace(".tmp", ".pdf").replace(".TMP", ".pdf")

        exporter = NrpPdfExporter()
        success = exporter.export_pdf(tmp_path, pdf_path)

        if success:
            print(f"Exported: {pdf_path}")
        else:
            print("Export failed")
            sys.exit(1)
