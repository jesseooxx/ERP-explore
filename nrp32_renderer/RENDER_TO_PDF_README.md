# TMP to PDF Renderer - Technical Documentation

**Created:** 2025-12-23
**Script:** `render_to_pdf.py`

## Overview

This script renders `.tmp` report files to PDF by combining two working DLLs:
- **nview32.dll**: Reads .tmp files and renders to Windows HDC (Device Context)
- **ChgPdf.dll**: Creates PDF files with basic text and graphics primitives

## What Works

### nview32.dll (Report Reader)
- `Constructor` - Creates CRptDoc object
- `Read(path)` - Loads .tmp file successfully
- `GetPageNum()` - Returns page count
- `GetSize(width, height)` - Returns page dimensions
- `ShowPage(hdc, page, x, y, w, h, scale)` - **Renders to memory DC successfully**

### ChgPdf.dll (PDF Writer)
- `PDF_open(filename, info)` - Creates PDF file
- `PDF_begin_page(pdf, width, height)` - Starts new page
- `PDF_set_font(pdf, font, size, encoding, embed)` - Sets font
- `PDF_show_xy(pdf, text, x, y)` - Draws text at position
- `PDF_end_page(pdf)` - Finishes page
- `PDF_close(pdf)` - Finalizes PDF

## Current Limitation

**CRITICAL ISSUE:** ChgPdf.dll does **NOT** have a function to save DC/bitmap content to PDF.

The following function we need does **NOT exist**:
```cpp
PDF_save_image(PDF_s* pdf, HDC hdc, int x, int y, int w, int h,
               double pdf_x, double pdf_y, double pdf_w, double pdf_h)
```

This means we can:
1. Read .tmp files
2. Render them to a memory DC (bitmap in memory)
3. Create PDF files
4. Add text to PDFs

But we **CANNOT**:
- Transfer the rendered bitmap from DC to PDF
- Capture the actual report content in PDF format

## What the Script Does

The current implementation:
1. Loads the .tmp file using nview32.dll
2. Gets page count and dimensions
3. For each page:
   - Creates a PDF page
   - Creates a memory DC
   - Renders the report page to the DC (this works!)
   - **Tries to add it to PDF** (this is where it fails)
   - Currently adds placeholder text instead
4. Saves the PDF

**Result:** You get a PDF with placeholder text saying "Page X - Rendering not fully supported" instead of actual report content.

## Why nview32's MakePdf Fails

According to our testing, all of nview32's built-in PDF functions fail:
- `MakePdf()` (3 different overloads)
- `AddToPdf()`
- `MakeRtf()`
- `MakeTxt()`

These all return 0 (failure), likely because:
1. Missing DATAWIN.INI configuration file
2. Missing registry keys
3. Missing COM initialization
4. Wrong working directory

## Possible Solutions

### Solution 1: Find PDF_save_image in ChgPdf.dll
Use a tool like Dependency Walker or IDA Pro to:
1. Examine all exports in ChgPdf.dll
2. Look for bitmap/image saving functions
3. Reverse engineer the function signature

### Solution 2: Screen Capture Approach
```python
# After ShowPage renders to DC:
1. Save DC content to BMP file
2. Use PIL/Pillow to convert BMP to image
3. Use reportlab to embed image in PDF
4. Delete temporary BMP
```

### Solution 3: GDI+ Metafile Approach
```python
# Create EMF (Enhanced Metafile) instead of bitmap:
1. Create EMF DC
2. ShowPage() to EMF DC
3. Save EMF
4. Convert EMF to PDF using external tool
```

### Solution 4: Fix nview32's MakePdf
Research what configuration files/settings are needed:
1. Create proper DATAWIN.INI
2. Set up registry keys
3. Initialize COM properly
4. May need to reverse engineer the DLL's initialization code

### Solution 5: GUI Automation (Already Implemented)
Use `nrp32_automation.py` which:
1. Launches nrp32.exe
2. Opens the .tmp file
3. Automates Ctrl+P (Print)
4. Selects "Microsoft Print to PDF"
5. Saves the output

**This is currently the most reliable method.**

## Requirements

- **32-bit Python** (py -3.12-32)
  - Both DLLs are 32-bit only
- **Windows OS**
- **DLLs in X:/EXE/**:
  - borlndmm.dll
  - cc32110mt.dll
  - nview32.dll
  - ChgPdf.dll

## Usage

```bash
# Run with 32-bit Python
py -3.12-32 render_to_pdf.py C:\temp\test.tmp C:\temp\output.pdf 150

# Arguments:
#   1. Input .tmp file path
#   2. Output .pdf file path (optional)
#   3. DPI resolution (optional, default 150)
```

## Current Output

Running the script will:
- Successfully load the .tmp file
- Report page count and dimensions
- Create a PDF file
- Each page will contain placeholder text explaining the limitation

**The PDF is created but does NOT contain the actual report content.**

## Recommended Next Steps

1. **Use GUI automation** (`nrp32_automation.py`) for production use
2. **Investigate ChgPdf.dll exports** to find image/bitmap functions
3. **Try screen capture approach** as intermediate solution
4. **Research DATAWIN.INI format** to fix nview32's MakePdf

## Technical Notes

### __thiscall Convention
nview32.dll uses MSVC's `__thiscall` convention where:
- `this` pointer is passed in ECX register
- We use machine code thunks to convert from cdecl:

```python
# Thunk: pop eax, pop ecx, push eax, jmp func_addr
code = [0x58, 0x59, 0x50, 0xE9] + rel_offset
```

### Memory DC Rendering
ShowPage successfully renders to memory DC:
```python
screen_dc = user32.GetDC(0)
mem_dc = gdi32.CreateCompatibleDC(screen_dc)
bitmap = gdi32.CreateCompatibleBitmap(screen_dc, width, height)
gdi32.SelectObject(mem_dc, bitmap)

# This works perfectly:
showpage(doc, mem_dc, page_num, 0, 0, width, height, 100)

# But then we can't get it into the PDF...
```

### ChgPdf.dll Exports (Confirmed Working)
```
?PDF_open@@YGPAUPDF_s@@PADPAUPDF_info@@@Z
?PDF_close@@YAXPAUPDF_s@@@Z
?PDF_begin_page@@YAXPAUPDF_s@@NN@Z
?PDF_end_page@@YAXPAUPDF_s@@@Z
?PDF_set_font@@YAXPAUPDF_s@@PADNW4PDF_encoding@@_N@Z
?PDF_show_xy@@YAXPAUPDF_s@@PADNN@Z
?PDF_get_info@@YAPAUPDF_info@@XZ
```

## Files Created

- `render_to_pdf.py` - Main rendering script
- `RENDER_TO_PDF_README.md` - This documentation
- Related files:
  - `nrp32_renderer.py` - Alternative using WNrpDll.dll
  - `nview_renderer.py` - Direct nview32 MakePdf calls
  - `nrp32_automation.py` - GUI automation (currently most reliable)

## Contact

For questions or improvements, see the main project README.

---

**Status:** PARTIAL IMPLEMENTATION - Creates PDF structure but cannot transfer rendered content due to missing ChgPdf.dll functions.
