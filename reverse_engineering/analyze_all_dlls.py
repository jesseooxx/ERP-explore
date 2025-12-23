"""
Analyze all DLLs in nrp_backup directory
"""

import pefile
import os
import re
from collections import defaultdict

BACKUP_DIR = r"C:\真桌面\Claude code\ERP explore\nrp_backup"

def extract_strings(filepath, min_length=4):
    """Extract ASCII and Unicode strings from binary file"""
    with open(filepath, 'rb') as f:
        data = f.read()

    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    ascii_strings = [s.decode('ascii') for s in re.findall(ascii_pattern, data)]

    # Unicode strings (simplified - UTF-16LE)
    unicode_strings = []
    i = 0
    while i < len(data) - 1:
        if data[i] >= 0x20 and data[i] <= 0x7e and data[i+1] == 0:
            # Start of potential unicode string
            start = i
            while i < len(data) - 1 and data[i] >= 0x20 and data[i] <= 0x7e and data[i+1] == 0:
                i += 2
            if (i - start) // 2 >= min_length:
                try:
                    s = data[start:i].decode('utf-16-le')
                    unicode_strings.append(s)
                except:
                    pass
        else:
            i += 1

    return ascii_strings, unicode_strings

def analyze_pe(filepath):
    """Analyze a PE file and return summary"""
    filename = os.path.basename(filepath)
    print(f"\n{'='*80}")
    print(f"ANALYZING: {filename}")
    print(f"{'='*80}")

    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        print(f"  Error loading PE: {e}")
        return None

    # Basic info
    print(f"\n[File Type]")
    if pe.is_dll():
        print(f"  Type: DLL")
    elif pe.is_exe():
        print(f"  Type: EXE")

    # Exports (most important for DLLs)
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"\n[EXPORTS] ({len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} functions)")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8', errors='ignore')
                exports.append(name)
                print(f"  - {name}")
    else:
        print(f"\n[EXPORTS] None")

    # Imports summary
    imports_by_dll = defaultdict(list)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\n[IMPORTS]")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode('utf-8', errors='ignore'))
            imports_by_dll[dll_name] = funcs
            print(f"  {dll_name}: {len(funcs)} functions")

    pe.close()

    # Extract strings
    print(f"\n[INTERESTING STRINGS]")
    ascii_strings, unicode_strings = extract_strings(filepath)
    all_strings = set(ascii_strings + unicode_strings)

    # Filter for interesting strings
    rendering_keywords = [
        'font', 'text', 'draw', 'paint', 'render', 'print', 'page',
        'margin', 'width', 'height', 'line', 'column', 'row',
        'report', 'template', 'layout', 'format', 'style',
        'pdf', 'rtf', 'xls', 'html', 'doc',
        'header', 'footer', 'title', 'section', 'band',
        'position', 'align', 'left', 'right', 'center', 'top', 'bottom',
        'pixel', 'point', 'inch', 'mm', 'cm',
        'bitmap', 'image', 'picture', 'graphic',
        'table', 'cell', 'border', 'grid',
        'rpt', 'nrp', 'datawin'
    ]

    interesting = set()
    for s in all_strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in rendering_keywords):
            if len(s) > 3 and len(s) < 200:  # Filter noise
                interesting.add(s)

    # Sort and print interesting strings
    for s in sorted(interesting)[:100]:  # Limit output
        print(f"  {s}")

    if len(interesting) > 100:
        print(f"  ... and {len(interesting) - 100} more")

    return {
        'exports': exports,
        'imports': imports_by_dll,
        'strings': interesting
    }

def main():
    print("NRP32 REVERSE ENGINEERING - DLL ANALYSIS")
    print("=" * 80)

    # Find all PE files
    pe_files = []
    for f in os.listdir(BACKUP_DIR):
        if f.lower().endswith(('.dll', '.exe')):
            pe_files.append(os.path.join(BACKUP_DIR, f))

    print(f"\nFound {len(pe_files)} PE files to analyze:")
    for f in pe_files:
        print(f"  - {os.path.basename(f)}")

    # Analyze each
    results = {}
    for pe_file in pe_files:
        results[os.path.basename(pe_file)] = analyze_pe(pe_file)

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY: KEY FINDINGS FOR DOCUMENT RENDERING")
    print("=" * 80)

    # Find report-related exports
    print("\n[Report/Rendering Related Exports]")
    for filename, data in results.items():
        if data and data['exports']:
            report_exports = [e for e in data['exports'] if any(
                kw in e.lower() for kw in ['report', 'rpt', 'page', 'render', 'draw', 'print', 'text', 'font', 'doc', 'make']
            )]
            if report_exports:
                print(f"\n  {filename}:")
                for exp in report_exports[:30]:
                    print(f"    - {exp}")

if __name__ == "__main__":
    main()
