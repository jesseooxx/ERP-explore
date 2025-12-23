# PI Generator - Quick Start Guide

## What is this?

`generate_pi.py` is a one-click solution to generate PI (Proforma Invoice) PDFs directly from your database, bypassing the slow ERP report system.

## Installation

No installation needed! Just make sure you have:
- Python 3.7+
- Database connection configured (already done in this project)
- PDF viewer (PDF-XChange Editor or any PDF viewer)

## Quick Start

### Generate a single PI
```bash
python generate_pi.py T17104
```

This will:
1. Query PI data from database
2. Generate PDF
3. Save to `Z:\LEILA\PI\{Cust#}\PI_ {Ref} ({ORDER}).pdf`
4. Open in PDF-XChange Editor (or default PDF viewer)

### Generate multiple PIs
```bash
python generate_pi.py T17104 T17103 I17109
```

### Test mode (save to local folder)
```bash
python generate_pi.py --test T17104
```
Saves to `./output/` instead of `Z:\LEILA\PI\`

### Batch processing (don't open PDFs)
```bash
python generate_pi.py --no-open T17104 T17103 I17109
```
Useful when generating many PIs at once.

### List available S/C numbers
```bash
python generate_pi.py --list
```

## Common Use Cases

### Case 1: Customer needs a PI right now
```bash
python generate_pi.py T17104
```
Done! PDF is saved and opened.

### Case 2: Generate PIs for multiple customers
```bash
python generate_pi.py T17104 T17103 I17109 B17106 C17110
```
All PDFs are generated and saved to their respective customer folders.

### Case 3: Daily PI generation from a list
Create a text file `pi_list.txt`:
```
T17104
T17103
I17109
```

Then run:
```bash
python generate_pi.py --no-open $(cat pi_list.txt)
```

### Case 4: Testing before sending to customer
```bash
python generate_pi.py --test T17104
```
Check the PDF in `./output/161/` before saving to production location.

## Command-Line Options

| Option | Description |
|--------|-------------|
| `sc_numbers` | One or more S/C numbers (e.g., T17104) |
| `--test` | Use test directory (./output) instead of production |
| `--no-open` | Don't open PDFs after generation |
| `--list` | List recent S/C numbers from database |
| `--limit N` | Number of S/C numbers to list (default: 20) |
| `--help` | Show help message |

## File Naming Convention

Generated PDFs follow the standard naming convention:
```
Z:\LEILA\PI\{Cust#}\PI_ {Ref} ({ORDER}).pdf
```

Example:
```
Z:\LEILA\PI\161\PI_ T17104 (11365).pdf
```

Where:
- `161` = Customer code
- `T17104` = S/C number
- `11365` = Customer PO number

## Error Messages

### "S/C number not found"
```
ERROR processing T99999: S/C T99999 not found in tfm01
```
**Solution**: Check the S/C number spelling. Use `--list` to see available S/C numbers.

### "Database connection failed"
**Solution**: Check database connection settings in `src/pi_generator/db.py`

### "Permission denied"
**Solution**: Check write permissions for `Z:\LEILA\PI\` directory

## Performance

- Single PI: ~1-1.5 seconds
- Batch processing: ~1 second per PI
- No practical limit on batch size

## Tips & Tricks

### Create a Windows shortcut
1. Right-click on desktop > New > Shortcut
2. Location: `python "C:\真桌面\Claude code\ERP explore\generate_pi.py" --list`
3. Name: "List PI S/C Numbers"

### Create a batch file for common tasks
Save as `generate_today_pis.bat`:
```batch
@echo off
echo Generating today's PIs...
python "C:\真桌面\Claude code\ERP explore\generate_pi.py" --no-open T17104 T17103 I17109
echo Done!
pause
```

### Process all recent PIs
```bash
python generate_pi.py --list --limit 50 > recent_sc.txt
# Edit recent_sc.txt to keep only S/C numbers you want
python generate_pi.py --no-open $(cat recent_sc.txt)
```

## Troubleshooting

### PDFs not opening automatically
- Make sure PDF-XChange Editor is installed, or
- Any PDF viewer is set as default for .pdf files

### Files saving to wrong location
- Use `--test` flag to save to local `./output/` directory
- Check that `Z:\LEILA\PI\` exists and is accessible

### "Total mismatch" warnings
These are informational warnings when calculated totals don't match master totals. The PDF is still generated correctly using the master total.

## Advanced Usage

### Integration with Excel
Use Excel VBA to call the script:
```vb
Shell "python C:\真桌面\Claude code\ERP explore\generate_pi.py " & Range("A1").Value
```

### Scheduled generation
Use Windows Task Scheduler to run daily:
```batch
python generate_pi.py --no-open $(cat daily_pi_list.txt)
```

## Support

For issues or questions, see:
- Implementation report: `TASK_5_REPORT.md`
- Database module docs: `src/pi_generator/pi_data.py`
- PDF generation docs: `src/pi_generator/pdf_generator.py`
- File management docs: `src/pi_generator/file_manager.py`

## Version

Version: 1.0.0
Date: 2025-12-23
Author: PI Generator Project
