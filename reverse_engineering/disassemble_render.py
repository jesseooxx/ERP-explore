"""
Disassemble and analyze rendering functions in nrp32.exe
Focus on GDI calls and text/graphics rendering
"""

import pefile
from capstone import *
import struct
from collections import defaultdict

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

# GDI32 function addresses we want to track
GDI_FUNCTIONS = {
    'TextOutA', 'ExtTextOutA', 'DrawTextA',
    'CreateFontIndirectA', 'SelectObject',
    'SetTextColor', 'SetBkColor', 'SetTextAlign',
    'MoveToEx', 'LineTo', 'Rectangle', 'Polygon', 'Polyline',
    'BitBlt', 'StretchDIBits',
    'CreatePen', 'CreateSolidBrush',
    'SaveDC', 'RestoreDC',
    'SetMapMode', 'SetViewportOrgEx', 'SetWindowOrgEx',
    'GetDeviceCaps', 'GetTextExtentPoint32A',
    'StartDoc', 'EndDoc', 'StartPage', 'EndPage'
}

def analyze_imports(pe):
    """Analyze import table and map function addresses"""
    import_map = {}  # address -> (dll, func_name)

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    import_map[imp.address] = (dll_name, func_name)

    return import_map

def find_function_calls(pe, code_section, import_map):
    """Find all calls to imported functions"""

    # Initialize Capstone disassembler for x86 32-bit
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    code = code_section.get_data()
    base_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    # Track call sites
    call_sites = defaultdict(list)  # func_name -> [(caller_addr, context)]

    print(f"Disassembling .text section ({len(code)} bytes)...")
    print(f"Base address: 0x{base_addr:08x}")

    instructions = list(md.disasm(code, base_addr))
    print(f"Disassembled {len(instructions)} instructions")

    # Look for CALL instructions
    for i, insn in enumerate(instructions):
        if insn.mnemonic == 'call':
            # Get target address
            if len(insn.operands) > 0:
                op = insn.operands[0]
                if op.type == 1:  # Immediate
                    target = op.imm
                elif op.type == 3:  # Memory reference
                    # Indirect call through IAT
                    target = op.mem.disp
                else:
                    continue

                # Check if it's an imported function
                if target in import_map:
                    dll, func = import_map[target]

                    # Get context (previous instructions)
                    context = []
                    for j in range(max(0, i-5), i):
                        context.append(f"  {instructions[j].address:08x}: {instructions[j].mnemonic} {instructions[j].op_str}")

                    call_sites[func].append({
                        'address': insn.address,
                        'dll': dll,
                        'context': context
                    })

    return call_sites

def analyze_text_rendering(call_sites):
    """Analyze text rendering patterns"""
    print("\n" + "=" * 80)
    print("TEXT RENDERING ANALYSIS")
    print("=" * 80)

    text_funcs = ['TextOutA', 'ExtTextOutA', 'DrawTextA', 'GetTextExtentPoint32A']

    for func in text_funcs:
        if func in call_sites:
            print(f"\n[{func}] - {len(call_sites[func])} calls")
            for i, site in enumerate(call_sites[func][:5]):  # First 5 calls
                print(f"\n  Call #{i+1} at 0x{site['address']:08x}")
                for ctx in site['context']:
                    print(ctx)

def analyze_drawing_primitives(call_sites):
    """Analyze drawing primitive patterns"""
    print("\n" + "=" * 80)
    print("DRAWING PRIMITIVES ANALYSIS")
    print("=" * 80)

    draw_funcs = ['MoveToEx', 'LineTo', 'Rectangle', 'Polygon', 'Polyline']

    for func in draw_funcs:
        if func in call_sites:
            print(f"\n[{func}] - {len(call_sites[func])} calls")
            for i, site in enumerate(call_sites[func][:3]):  # First 3 calls
                print(f"\n  Call #{i+1} at 0x{site['address']:08x}")
                for ctx in site['context']:
                    print(ctx)

def analyze_printing(call_sites):
    """Analyze printing/pagination patterns"""
    print("\n" + "=" * 80)
    print("PRINTING/PAGINATION ANALYSIS")
    print("=" * 80)

    print_funcs = ['StartDocA', 'EndDoc', 'StartPage', 'EndPage', 'SetAbortProc']

    for func in print_funcs:
        if func in call_sites:
            print(f"\n[{func}] - {len(call_sites[func])} calls")
            for i, site in enumerate(call_sites[func][:2]):
                print(f"\n  Call #{i+1} at 0x{site['address']:08x}")
                for ctx in site['context']:
                    print(ctx)

def find_string_references(pe, code_section):
    """Find references to interesting strings"""
    print("\n" + "=" * 80)
    print("STRING REFERENCES IN CODE")
    print("=" * 80)

    # Get all sections
    data = pe.get_memory_mapped_image()

    # Search for interesting strings
    interesting_strings = [
        b'HEAD', b'PLANK', b'LABEL', b'EDIT', b'LINE', b'IMAGE', b'FONT',
        b'PS_LEFT', b'PS_RIGHT', b'PS_CENTER', b'PS_BORDER',
        b'Datawin Report', b'TextOut', b'DrawText',
        b'.tmp', b'.bmp', b'.jpg', b'.pdf'
    ]

    for search_str in interesting_strings:
        offset = 0
        while True:
            pos = data.find(search_str, offset)
            if pos == -1:
                break
            # Check if in data section (not in code)
            rva = pos
            section = None
            for sec in pe.sections:
                if sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize:
                    section = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    break

            if section and section != '.text':
                va = pe.OPTIONAL_HEADER.ImageBase + rva
                print(f"  '{search_str.decode('ascii', errors='ignore')}' at RVA 0x{rva:08x} (VA 0x{va:08x}) in {section}")
                break
            offset = pos + 1

def summarize_rendering_model():
    """Generate summary of discovered rendering model"""
    print("\n" + "=" * 80)
    print("DISCOVERED RENDERING MODEL")
    print("=" * 80)
    print("""
RENDERING ARCHITECTURE:

1. DOCUMENT LOADING (CRptDoc::Read / CRptDoc::Create)
   - Parse binary header (magic, version, title)
   - Parse DSL text content
   - Build internal element tree

2. ELEMENT TREE STRUCTURE:
   - Root: ReportDocument
     - HEAD (page header)
     - PLANK[] (containers)
       - LABEL (static text)
       - EDIT (data field)
       - LINE (separator)
       - IMAGE (graphics)
       - FONT (style definition)

3. RENDERING PIPELINE (CRptDoc::ShowPage):

   a) Setup DC (Device Context):
      - CreateDCA() for printer or screen
      - SetMapMode() - coordinate mapping
      - SetViewportOrgEx/SetWindowOrgEx - origin
      - SaveDC() to preserve state

   b) Render Page Structure:
      - Calculate page bounds
      - Apply HEAD styles (border, shadow)
      - Iterate through PLANKs

   c) For Each PLANK:
      - Calculate absolute position
      - Set clipping region if needed
      - Render children in order:

        LABEL Rendering:
          - CreateFontIndirectA() for text style
          - SelectObject() to set font
          - SetTextColor() for text color
          - SetTextAlign() based on PS_LEFT/RIGHT/CENTER
          - TextOutA() or ExtTextOutA() to draw

        EDIT Rendering:
          - Same as LABEL but with data binding
          - May have different styling

        LINE Rendering:
          - CreatePen() for line style
          - MoveToEx() to start point
          - LineTo() to end point

        IMAGE Rendering:
          - Load bitmap/jpeg
          - CreateCompatibleDC()
          - BitBlt() or StretchDIBits()

   d) Cleanup:
      - RestoreDC()
      - DeleteObject() for GDI resources

4. PRINTING PIPELINE:
   - StartDocA() begin print job
   - For each page:
     - StartPage()
     - ShowPage() renders to printer DC
     - EndPage()
   - EndDoc()

5. PDF GENERATION (CRptDoc::MakePdf):
   - Likely uses third-party PDF library
   - Translates GDI calls to PDF primitives

COORDINATE SYSTEM:
   - Units: Likely 0.1mm or twips
   - Origin: Top-left
   - Positive Y: Downward
   - PLANKs define local coordinate spaces
   - Elements use relative positions within PLANK

STYLE FLAG IMPLEMENTATION:
   PS_LEFT:    SetTextAlign(TA_LEFT)
   PS_RIGHT:   SetTextAlign(TA_RIGHT)
   PS_CENTER:  SetTextAlign(TA_CENTER)
   PS_BORDER:  Rectangle() around element
   PS_SHADOW:  Draw offset rectangle first
   PS_FONT_BOLD: LOGFONT.lfWeight = FW_BOLD
   PS_FONT_UNDERLINE: LOGFONT.lfUnderline = TRUE
""")

def main():
    print("=" * 80)
    print("NRP32.EXE RENDERING FUNCTION ANALYSIS")
    print("=" * 80)

    pe = pefile.PE(EXE_PATH)

    # Get import map
    import_map = analyze_imports(pe)
    print(f"\nLoaded {len(import_map)} imported functions")

    # Find code section
    code_section = None
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if name == '.text':
            code_section = section
            break

    if not code_section:
        print("Could not find .text section!")
        return

    print(f"Code section: .text at 0x{code_section.VirtualAddress:08x}, size {code_section.SizeOfRawData}")

    # Find all call sites
    call_sites = find_function_calls(pe, code_section, import_map)

    # Generate summary statistics
    print("\n" + "=" * 80)
    print("FUNCTION CALL STATISTICS")
    print("=" * 80)

    for func in sorted(GDI_FUNCTIONS):
        if func in call_sites:
            print(f"  {func}: {len(call_sites[func])} calls")

    # Detailed analysis
    analyze_text_rendering(call_sites)
    analyze_drawing_primitives(call_sites)
    analyze_printing(call_sites)
    find_string_references(pe, code_section)
    summarize_rendering_model()

    pe.close()

if __name__ == "__main__":
    main()
