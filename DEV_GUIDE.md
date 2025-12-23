# ERP Explore - Development Guide

## Overview

This project explores DataWin ERP system internals for PDF rendering optimization.

## Project Structure

```
ERP explore/
  nrp32_renderer/       # Native DLL renderer (32-bit Python)
    dll/                # Extracted DLLs from ERP
    nrp32_renderer.py   # WNrpDll.dll wrapper
    nview_renderer.py   # nview32.dll wrapper (has MakePdf)
    setup_env.bat       # Environment setup
    render.bat          # Quick render script
  reverse_engineering/  # Analysis tools
    dwzp_extractor.py   # DWZP backup extractor
    Bkup.a01            # ERP system backup
  src/
    tmp_parser/         # TMP file parser
    pi_generator/       # PI document generator
  nrp_backup/           # Original DLL backup
```

## 32-bit Python Setup

### Why 32-bit?
All DataWin DLLs (WNrpDll.dll, nview32.dll, NrpDll.dll) are compiled for 32-bit x86.

### Installation

1. Download Python 3.12.10 32-bit from:
   https://www.python.org/downloads/release/python-31210/

   Select: "Windows installer (32-bit)" (python-3.12.10.exe, 24.5 MB)

   Note: Python 3.12.11+ no longer provides binary installers.

2. Install to: `C:\Users\<user>\AppData\Local\Programs\Python\Python312-32`

3. Verify:
   ```batch
   "C:\Users\<user>\AppData\Local\Programs\Python\Python312-32\python.exe" -c "import struct; print(struct.calcsize('P')*8, 'bit')"
   ```
   Should output: `32 bit`

### Virtual Environment

```batch
cd nrp32_renderer
setup_env.bat
```

Or manually:
```batch
"C:\Users\user\AppData\Local\Programs\Python\Python312-32\python.exe" -m venv .venv32
.venv32\Scripts\activate
pip install pywin32
```

## DLL Rendering Status

### WNrpDll.dll (Borland C++)

**Available Functions:**
- Constructor: Yes
- Read: Yes
- GetPageNum: Yes
- GetSize: Yes
- ShowPage: Yes (crashes - calling convention issue)
- MakeRtf: Yes
- MakeTxt: Yes
- MakeXls: Yes

**Issue:** Borland `__fastcall` passes `this` in EAX register, which Python ctypes cannot handle.

**Workaround:** RTF/TXT/XLS export works because they're simpler function calls.

### nview32.dll (MSVC)

**Available Function:**
- MakePdf: Yes (signature: `?MakePdf@CRptDoc@@QAEHPADHHHHHHHHNNN@Z`)

**Issue:** Missing Borland runtime DLL dependencies (borlndmm.dll, cc32110mt.dll).

## Working Export Methods

### 1. RTF Export (Works)
```python
from nrp32_renderer import NrpDllWrapper

wrapper = NrpDllWrapper()
wrapper.load_file("input.tmp")
wrapper.export_rtf("output.rtf")
wrapper.close()
```

### 2. TXT Export (Works)
```python
wrapper.export_txt("output.txt")
```

### 3. XLS Export (Works)
```python
wrapper.export_xls("output.xls")
```

## DWZP Backup Format

DataWin uses DWZP format for backups (.a01 files).

### Format Structure
```
+0:  DWZP (4 bytes magic)
+4:  8 bytes (unknown/zeros)
+12: compressed_size (4 bytes, little-endian)
+16: 4 bytes (unknown/zeros)
+20: path_length (2 bytes, little-endian)
+22: 2 bytes (unknown/zeros)
+24: path string
After path: raw deflate compressed data (-15 wbits)
```

### Usage
```batch
# List files in backup
python reverse_engineering/dwzp_extractor.py Bkup.a01 --list

# Extract all files
python reverse_engineering/dwzp_extractor.py Bkup.a01 extracted/

# Extract only source code
python reverse_engineering/dwzp_extractor.py Bkup.a01 --source
```

## Extracted DLLs

From the backup, we extracted:
- nview32.dll (2.1 MB) - Has native MakePdf function
- WNrpDll.dll (2.9 MB) - Report viewer DLL
- NrpDll.dll (1.8 MB) - Core report DLL
- MakeReport.dll (447 KB) - Report generation
- NrpOle.dll (40 KB) - OLE support
- nrp32.exe (447 KB) - GUI viewer
- borlndmm.dll (24 KB) - Borland Memory Manager
- cc32110mt.dll (1 MB) - Borland C++ Runtime

## Next Steps

1. **Fix nview32.dll loading**: Add Borland runtime DLLs to PATH
2. **Test MakePdf**: Once dependencies resolved, test direct PDF generation
3. **Alternative**: Use subprocess with nrp32.exe + virtual printer if DLL approach fails

## Performance Comparison

| Method | Time | Quality |
|--------|------|---------|
| nrp32.exe GUI | 30-60s | Perfect |
| DLL MakePdf (goal) | <1s | Perfect |
| RTF export + convert | 2-3s | Good |
| PyMuPDF custom render | 0.2s | Approximate |

## Troubleshooting

### "This module requires 32-bit Python"
Use Python from: `C:\Users\user\AppData\Local\Programs\Python\Python312-32\python.exe`

### Segmentation fault on DLL call
Borland calling convention issue. Use RTF/TXT export as workaround.

### "Could not find module (or dependencies)"
Missing Borland runtime DLLs. Ensure borlndmm.dll and cc32110mt.dll are in PATH or same directory.
