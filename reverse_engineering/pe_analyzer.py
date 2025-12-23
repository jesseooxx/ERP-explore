"""
PE File Analyzer for nrp32.exe
Analyzes PE structure, imports, exports, resources, and strings
"""

import pefile
import os
import struct
from collections import defaultdict

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def analyze_pe():
    print("=" * 80)
    print("NRP32.EXE PE ANALYSIS")
    print("=" * 80)

    pe = pefile.PE(EXE_PATH)

    # Basic info
    print("\n[1] BASIC PE INFORMATION")
    print("-" * 40)
    print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"Number of sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

    if hasattr(pe, 'OPTIONAL_HEADER'):
        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")

    # Sections
    print("\n[2] SECTIONS")
    print("-" * 40)
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"  {name:8} VA:{hex(section.VirtualAddress):10} Size:{section.SizeOfRawData:8} Entropy:{section.get_entropy():.2f}")

    # Imports - CRITICAL for understanding rendering
    print("\n[3] IMPORTS (DLLs and Functions)")
    print("-" * 40)

    rendering_related = []
    printing_related = []
    gdi_functions = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            print(f"\n  DLL: {dll_name}")

            imports = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    imports.append(func_name)

                    # Categorize rendering-related functions
                    func_lower = func_name.lower()
                    if any(x in func_lower for x in ['draw', 'paint', 'render', 'text', 'font', 'dc', 'gdi']):
                        rendering_related.append((dll_name, func_name))
                    if any(x in func_lower for x in ['print', 'page', 'spool']):
                        printing_related.append((dll_name, func_name))
                    if 'GDI32' in dll_name.upper():
                        gdi_functions.append(func_name)

            # Print first 20 imports per DLL
            for func in imports[:20]:
                print(f"    - {func}")
            if len(imports) > 20:
                print(f"    ... and {len(imports) - 20} more")

    # Summarize rendering-related imports
    print("\n[4] RENDERING-RELATED FUNCTIONS")
    print("-" * 40)
    if rendering_related:
        for dll, func in rendering_related:
            print(f"  {dll}: {func}")
    else:
        print("  No obvious rendering functions found in imports")

    print("\n[5] PRINTING-RELATED FUNCTIONS")
    print("-" * 40)
    if printing_related:
        for dll, func in printing_related:
            print(f"  {dll}: {func}")

    print("\n[6] GDI32 FUNCTIONS (Graphics Device Interface)")
    print("-" * 40)
    if gdi_functions:
        for func in gdi_functions:
            print(f"  - {func}")

    # Exports
    print("\n[7] EXPORTS")
    print("-" * 40)
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                print(f"  {exp.name.decode('utf-8', errors='ignore')}")
    else:
        print("  No exports")

    # Resources
    print("\n[8] RESOURCES")
    print("-" * 40)
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def parse_resources(resource, level=0):
            if hasattr(resource, 'data'):
                # It's a ResourceDataEntry
                return
            if hasattr(resource, 'entries'):
                for entry in resource.entries:
                    if hasattr(entry, 'id'):
                        res_type = entry.id
                        type_names = {
                            1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU',
                            5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT',
                            9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE',
                            12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION',
                            24: 'MANIFEST'
                        }
                        type_name = type_names.get(res_type, f"TYPE_{res_type}")
                        print(f"  {'  ' * level}{type_name} (ID: {res_type})")
                    if hasattr(entry, 'name') and entry.name:
                        print(f"  {'  ' * level}Named: {entry.name}")
                    if hasattr(entry, 'directory'):
                        parse_resources(entry.directory, level + 1)

        parse_resources(pe.DIRECTORY_ENTRY_RESOURCE)
    else:
        print("  No resources")

    pe.close()
    return pe

if __name__ == "__main__":
    analyze_pe()
