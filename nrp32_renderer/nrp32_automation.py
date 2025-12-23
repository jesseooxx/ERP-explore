"""
NRP32 GUI Automation - Generates PDF using nrp32.exe with pywinauto

This automates the nrp32.exe GUI to print to PDF when direct DLL calls fail.
"""
import os
import time
import subprocess
from pathlib import Path

def find_nrp32_exe():
    """Find nrp32.exe in common locations"""
    paths = [
        Path(__file__).parent / "dll" / "nrp32.exe",
        Path(__file__).parent.parent / "nrp_backup" / "nrp32.exe",
        Path("C:/DataWin/exe/nrp32.exe"),
    ]
    for p in paths:
        if p.exists():
            return str(p)
    return None


def render_with_automation(tmp_path: str, pdf_path: str, timeout: int = 60) -> bool:
    """
    Render TMP to PDF using GUI automation.

    Args:
        tmp_path: Input .tmp file
        pdf_path: Output .pdf file
        timeout: Maximum seconds to wait

    Returns:
        True if successful
    """
    try:
        from pywinauto import Application
        from pywinauto.keyboard import send_keys
    except ImportError:
        print("pywinauto not installed. Run: pip install pywinauto")
        return False

    nrp32_exe = find_nrp32_exe()
    if not nrp32_exe:
        print("nrp32.exe not found")
        return False

    tmp_path = os.path.abspath(tmp_path)
    pdf_path = os.path.abspath(pdf_path)

    if not os.path.exists(tmp_path):
        print(f"Input file not found: {tmp_path}")
        return False

    # Ensure output directory exists
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

    print(f"Starting nrp32.exe...")
    print(f"  Input: {tmp_path}")
    print(f"  Output: {pdf_path}")

    try:
        # Start nrp32.exe with the TMP file
        app = Application(backend="win32").start(f'"{nrp32_exe}" "{tmp_path}"')

        # Wait for main window
        time.sleep(2)

        # Find the main window
        main_window = app.top_window()
        print(f"Window: {main_window.window_text()}")

        # Bring to front
        main_window.set_focus()
        time.sleep(0.5)

        # Send Ctrl+P to print
        print("Sending print command...")
        send_keys('^p')
        time.sleep(1)

        # Wait for print dialog
        print_dlg = app.window(title_re=".*Print.*|.*列印.*")
        print_dlg.wait('visible', timeout=10)
        print("Print dialog opened")

        # Select PDF printer (Microsoft Print to PDF)
        # This part may need adjustment based on the actual dialog

        # Try to find printer dropdown/combo
        try:
            printer_combo = print_dlg.child_window(class_name="ComboBox")
            printer_combo.select("Microsoft Print to PDF")
        except:
            # Or try typing the printer name
            pass

        # Click OK/Print button
        try:
            ok_btn = print_dlg.child_window(title_re="OK|确定|Print|列印")
            ok_btn.click()
        except:
            send_keys('{ENTER}')

        time.sleep(1)

        # Wait for "Save As" dialog
        save_dlg = app.window(title_re=".*Save.*|.*另存.*|.*储存.*")
        save_dlg.wait('visible', timeout=10)
        print("Save dialog opened")

        # Enter filename
        filename_edit = save_dlg.child_window(class_name="Edit")
        filename_edit.set_text(pdf_path)

        # Click Save
        time.sleep(0.5)
        send_keys('{ENTER}')

        # Wait for PDF to be created
        print("Waiting for PDF creation...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if os.path.exists(pdf_path):
                time.sleep(1)  # Wait a bit more for file to be fully written
                size = os.path.getsize(pdf_path)
                print(f"PDF created! Size: {size:,} bytes")

                # Close nrp32
                main_window.close()
                return True
            time.sleep(0.5)

        print("Timeout waiting for PDF")
        main_window.close()
        return False

    except Exception as e:
        print(f"Automation error: {e}")
        import traceback
        traceback.print_exc()

        # Try to close any open nrp32 windows
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'nrp32.exe'],
                          capture_output=True, timeout=5)
        except:
            pass

        return False


def main():
    import sys

    if len(sys.argv) < 2:
        print("NRP32 GUI Automation PDF Generator")
        print()
        print("Usage: python nrp32_automation.py <input.tmp> [output.pdf]")
        return

    tmp_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else tmp_path.replace('.tmp', '.pdf')

    success = render_with_automation(tmp_path, pdf_path)
    print()
    print("SUCCESS" if success else "FAILED")


if __name__ == '__main__':
    main()
