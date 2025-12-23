# Quick Start Guide - TMP to PDF Renderer

## Installation

### 1. Install 32-bit Python
Download from: https://www.python.org/downloads/
- Select "Windows installer (32-bit)"
- Install to default location
- Verify: `py -3.12-32 --version`

### 2. Install Required Packages
```bash
py -3.12-32 -m pip install pillow reportlab
```

### 3. Verify DLLs
Check that these files exist in `X:/EXE/`:
- borlndmm.dll
- cc32110mt.dll
- nview32.dll

## Usage

### Basic Command
```bash
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp output.pdf
```

### With Custom DPI
```bash
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp output.pdf 200
```

### Using Batch File
```bash
test_render.bat
```

## Examples

### Example 1: Default Output
```bash
cd C:\真桌面\Claude code\ERP explore\nrp32_renderer
py -3.12-32 render_to_pdf_enhanced.py C:\temp\report.tmp
# Creates: C:\temp\report.pdf
```

### Example 2: Custom Location
```bash
py -3.12-32 render_to_pdf_enhanced.py C:\temp\input.tmp D:\output\result.pdf
```

### Example 3: High Quality
```bash
py -3.12-32 render_to_pdf_enhanced.py C:\temp\input.tmp output.pdf 300
```

## Common Issues

### "This script requires 32-bit Python"
**Solution:** Use `py -3.12-32` instead of `python` or `py`

### "PIL/Pillow not installed"
**Solution:**
```bash
py -3.12-32 -m pip install pillow
```

### "reportlab not installed"
**Solution:**
```bash
py -3.12-32 -m pip install reportlab
```

### "DLL directory not found: X:/EXE/"
**Solution:** Verify the DLLs are in the correct location

### "Failed to read .tmp file"
**Solution:**
- Check file path is correct
- Ensure file is a valid .tmp report file
- Make sure you're running from X:/EXE/ or script changes directory automatically

## Output

### What You Get
- PDF file with actual report content
- Each page rendered as high-quality image
- File size: ~100-200KB per page (typical)

### Quality Settings (DPI)
- **72 DPI** - Low quality, small file (screen preview)
- **150 DPI** - Good quality, medium file (default, recommended)
- **200 DPI** - High quality, larger file (printing)
- **300 DPI** - Very high quality, large file (professional printing)

## File Locations

### Scripts
- `render_to_pdf_enhanced.py` - Main working script
- `render_to_pdf.py` - Alternative (skeleton only)
- `test_render.bat` - Test script

### Documentation
- `QUICK_START.md` - This file
- `IMPLEMENTATION_SUMMARY.md` - Technical overview
- `RENDER_TO_PDF_README.md` - Detailed technical docs

### DLLs Required
- `X:/EXE/borlndmm.dll`
- `X:/EXE/cc32110mt.dll`
- `X:/EXE/nview32.dll`

## Performance

Typical rendering times:
- 1 page: ~1-2 seconds
- 4 pages: ~3-4 seconds
- 10 pages: ~7-10 seconds

## Tips

1. **Use default DPI (150)** for most cases
2. **Check file size** if PDF is too large, reduce DPI
3. **Keep DLLs in X:/EXE/** - don't move them
4. **Use 32-bit Python** - 64-bit won't work
5. **Test with small files first** before batch processing

## Troubleshooting Commands

### Check Python Version
```bash
py -3.12-32 --version
```

### Check Installed Packages
```bash
py -3.12-32 -m pip list | findstr -i "pillow reportlab"
```

### Test DLL Loading
```bash
py -3.12-32 -c "import ctypes; print(ctypes.CDLL('X:/EXE/nview32.dll'))"
```

### Verify 32-bit
```bash
py -3.12-32 -c "import struct; print(f'{struct.calcsize(\"P\") * 8}-bit')"
```

## Getting Help

If you encounter issues:
1. Check this guide's Common Issues section
2. Review IMPLEMENTATION_SUMMARY.md for technical details
3. Check error messages carefully
4. Verify all requirements are met

## Success Indicators

When it works correctly, you should see:
```
Loading DLLs...
DLLs loaded successfully

Loading: C:\temp\test.tmp
Pages: 4
Size: 666 x 990

Rendering to PDF: output.pdf
DPI: 150
PDF page size: 319.7 x 475.2 points
  Rendering page 1/4...
  Rendering page 2/4...
  Rendering page 3/4...
  Rendering page 4/4...

SUCCESS! PDF created: 487,234 bytes
Contains 4 page(s) with actual report content

COMPLETE - PDF contains actual report content!
```

## Ready to Use!

You're all set. Try running:
```bash
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp
```

And check the output PDF.
