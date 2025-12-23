"""
Analyze the sample_report.tmp file format
"""

import struct
import os
import re

TEMPLATE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"

def hexdump(data, length=16, start=0):
    """Pretty print hex dump"""
    result = []
    for i in range(0, min(len(data), 2000), length):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+length])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+length])
        result.append(f'{start+i:08x}  {hex_part:<{length*3}}  {ascii_part}')
    return '\n'.join(result)

def find_strings(data, min_length=4):
    """Find ASCII strings in binary data"""
    strings = []
    current = b''
    start_pos = 0

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start_pos = i
            current += bytes([b])
        else:
            if len(current) >= min_length:
                strings.append((start_pos, current.decode('ascii', errors='ignore')))
            current = b''

    if len(current) >= min_length:
        strings.append((start_pos, current.decode('ascii', errors='ignore')))

    return strings

def analyze_structure(data):
    """Try to identify structure patterns"""
    print("\n[STRUCTURE ANALYSIS]")

    # Check for common file signatures
    signatures = {
        b'\x89PNG': 'PNG Image',
        b'BM': 'BMP Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'PK\x03\x04': 'ZIP/PKZIP',
        b'%PDF': 'PDF Document',
        b'RIFF': 'RIFF Container',
        b'MZ': 'DOS/PE Executable',
        b'\x00\x00\x01\x00': 'ICO Image',
        b'{\rtf': 'RTF Document',
    }

    print(f"  File size: {len(data)} bytes")
    print(f"  First 4 bytes: {data[:4].hex()}")
    print(f"  First 8 bytes: {data[:8].hex()}")

    for sig, desc in signatures.items():
        if data.startswith(sig):
            print(f"  Detected signature: {desc}")
            break

    # Look for repeated patterns
    print("\n  Looking for version/magic numbers...")
    if len(data) >= 4:
        first_word = struct.unpack('<I', data[:4])[0]
        print(f"  First DWORD (LE): {first_word} (0x{first_word:08x})")

    if len(data) >= 8:
        first_qword = struct.unpack('<Q', data[:8])[0]
        print(f"  First QWORD (LE): {first_qword}")

    # Look for null-terminated strings at fixed positions
    print("\n  Checking for header strings...")
    for pos in [0, 4, 8, 16, 32, 64, 128]:
        if pos < len(data):
            end = data.find(b'\x00', pos)
            if end > pos and end - pos < 256:
                s = data[pos:end]
                if all(32 <= b < 127 for b in s) and len(s) > 2:
                    print(f"  @{pos}: \"{s.decode('ascii')}\"")

def main():
    print("=" * 80)
    print("SAMPLE_REPORT.TMP ANALYSIS")
    print("=" * 80)

    with open(TEMPLATE_PATH, 'rb') as f:
        data = f.read()

    print(f"\nFile size: {len(data)} bytes ({len(data)/1024:.2f} KB)")

    # Hex dump of first 512 bytes
    print("\n[HEX DUMP - First 512 bytes]")
    print(hexdump(data[:512]))

    # Analyze structure
    analyze_structure(data)

    # Find strings
    print("\n[EMBEDDED STRINGS]")
    strings = find_strings(data, min_length=5)
    print(f"Found {len(strings)} strings")

    # Categorize strings
    report_keywords = ['report', 'font', 'text', 'page', 'print', 'margin', 'width', 'height',
                       'left', 'right', 'top', 'bottom', 'align', 'border', 'column', 'row',
                       'header', 'footer', 'title', 'data', 'field', 'band', 'section']

    interesting = []
    for pos, s in strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in report_keywords) or len(s) > 20:
            interesting.append((pos, s))

    print("\n  Interesting strings:")
    for pos, s in interesting[:100]:
        print(f"  @{pos:06x}: {s[:80]}{'...' if len(s) > 80 else ''}")

    # Check for XML/HTML-like tags
    print("\n  Looking for markup tags...")
    tag_pattern = re.compile(rb'<[^>]+>')
    tags = tag_pattern.findall(data)
    if tags:
        unique_tags = set(t.decode('ascii', errors='ignore') for t in tags[:50])
        for tag in sorted(unique_tags)[:30]:
            print(f"    {tag}")

    # Look for binary record structures
    print("\n[BINARY RECORD ANALYSIS]")

    # Check if there are repeated 4-byte aligned structures
    dwords = []
    for i in range(0, min(len(data), 256), 4):
        dwords.append(struct.unpack('<I', data[i:i+4])[0])

    print("  First 64 DWORDs:")
    for i in range(0, min(64, len(dwords)), 8):
        row = dwords[i:i+8]
        print(f"  {i*4:04x}: " + " ".join(f"{d:08x}" for d in row))

    # Try to identify record boundaries
    print("\n  Looking for record markers...")
    common_markers = [0x00000000, 0xFFFFFFFF, 0x00010000, 0x00020000]
    for marker in common_markers:
        count = dwords.count(marker)
        if count > 0:
            print(f"  Marker 0x{marker:08x} appears {count} times in first 256 bytes")

if __name__ == "__main__":
    main()
