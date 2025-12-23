"""
NRP Report DSL Parser
Parses the Datawin Report format and documents the rendering model
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntFlag, auto

# Position/Style flags discovered from the report format
class PSFlags(IntFlag):
    PS_LEFT = 1
    PS_RIGHT = 2
    PS_CENTER = 4
    PS_BORDER = 8
    PS_SHADOW = 16
    PS_FONT_BOLD = 32
    PS_FONT_UNDERLINE = 64
    PS_RESERVED3 = 128

@dataclass
class ReportElement:
    """Base class for report elements"""
    element_type: str
    id_type: str = ""
    id_num: int = 0
    style_flags: str = ""
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0
    raw: str = ""

@dataclass
class LabelElement(ReportElement):
    text: str = ""

@dataclass
class EditElement(ReportElement):
    pass

@dataclass
class ImageElement(ReportElement):
    image_path: str = ""

@dataclass
class LineElement(ReportElement):
    thickness: int = 1
    x2: int = 0
    y2: int = 0

@dataclass
class FontElement(ReportElement):
    font_name: str = ""
    font_size: int = 12
    font_style: str = ""

@dataclass
class PlankElement(ReportElement):
    """Container/Panel element"""
    children: List[ReportElement] = field(default_factory=list)

@dataclass
class HeadElement(ReportElement):
    head_size: int = 0

@dataclass
class ReportDocument:
    """Complete report document"""
    magic: str = ""
    title: str = ""
    version_info: Dict = field(default_factory=dict)
    elements: List[ReportElement] = field(default_factory=list)

class ReportParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.content = b""
        self.text_content = ""
        self.document = ReportDocument()

    def load(self):
        with open(self.filepath, 'rb') as f:
            self.content = f.read()

        # Extract text portion (after binary header)
        # The DSL text starts after the null-terminated header
        text_start = 0
        for i in range(len(self.content)):
            if self.content[i:i+4] == b'HEAD':
                text_start = i
                break

        self.text_content = self.content[text_start:].decode('ascii', errors='ignore')

    def parse_header(self):
        """Parse the binary header"""
        if self.content[:14] == b'Datawin Report':
            self.document.magic = "Datawin Report"

        # Parse version info at offset 0x20
        if len(self.content) >= 0x48:
            version_data = struct.unpack('<8I', self.content[0x20:0x40])
            self.document.version_info = {
                'v1': version_data[0],
                'plank_count': version_data[1],
                'element_count': version_data[2],
                'v4': version_data[3],
                'v5': version_data[4],
                'v6': version_data[5],
                'v7': version_data[6],
                'v8': version_data[7],
            }

        # Extract title (at offset 0x48)
        title_end = self.content.find(b'\x00', 0x48)
        if title_end > 0x48:
            self.document.title = self.content[0x48:title_end].decode('ascii', errors='ignore')

    def parse_elements(self):
        """Parse DSL elements from text content"""

        # Regular expression patterns for each element type
        patterns = {
            'HEAD': r'HEAD\s+(\d+),\s*([^,\n]+)',
            'PLANK': r'PLANK\s+ID_PLANK\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LABEL': r'LABEL\s+"([^"]*)",\s*ID_LABEL\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'EDIT': r'EDIT\s+ID_EDIT\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LINE': r'LINE\s*,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'IMAGE': r'IMAGE\s+"([^"]+)"\s*,\s*ID_LABEL\+\s*(\d+),\s*([^,]+)',
            'FONT': r'FONT\s+"([^"]*)",\s*(\d+),\s*([^\n]+)',
        }

        for elem_type, pattern in patterns.items():
            for match in re.finditer(pattern, self.text_content):
                elem = self._create_element(elem_type, match)
                if elem:
                    self.document.elements.append(elem)

    def _create_element(self, elem_type: str, match) -> Optional[ReportElement]:
        """Create appropriate element from regex match"""
        try:
            if elem_type == 'HEAD':
                return HeadElement(
                    element_type='HEAD',
                    head_size=int(match.group(1)),
                    style_flags=match.group(2).strip(),
                    raw=match.group(0)
                )
            elif elem_type == 'PLANK':
                return PlankElement(
                    element_type='PLANK',
                    id_type='ID_PLANK',
                    id_num=int(match.group(1)),
                    style_flags=match.group(2).strip(),
                    x=int(match.group(3)),
                    y=int(match.group(4)),
                    width=int(match.group(5)),
                    height=int(match.group(6)),
                    raw=match.group(0)
                )
            elif elem_type == 'LABEL':
                return LabelElement(
                    element_type='LABEL',
                    text=match.group(1),
                    id_type='ID_LABEL',
                    id_num=int(match.group(2)),
                    style_flags=match.group(3).strip(),
                    x=int(match.group(4)),
                    y=int(match.group(5)),
                    width=int(match.group(6)),
                    height=int(match.group(7)),
                    raw=match.group(0)
                )
            elif elem_type == 'EDIT':
                return EditElement(
                    element_type='EDIT',
                    id_type='ID_EDIT',
                    id_num=int(match.group(1)),
                    style_flags=match.group(2).strip(),
                    x=int(match.group(3)),
                    y=int(match.group(4)),
                    width=int(match.group(5)),
                    height=int(match.group(6)),
                    raw=match.group(0)
                )
            elif elem_type == 'LINE':
                return LineElement(
                    element_type='LINE',
                    thickness=int(match.group(1)),
                    x=int(match.group(2)),
                    y=int(match.group(3)),
                    x2=int(match.group(4)),
                    y2=int(match.group(5)),
                    raw=match.group(0)
                )
            elif elem_type == 'IMAGE':
                return ImageElement(
                    element_type='IMAGE',
                    image_path=match.group(1),
                    id_type='ID_LABEL',
                    id_num=int(match.group(2)),
                    style_flags=match.group(3).strip(),
                    raw=match.group(0)
                )
            elif elem_type == 'FONT':
                return FontElement(
                    element_type='FONT',
                    font_name=match.group(1),
                    font_size=int(match.group(2)),
                    font_style=match.group(3).strip(),
                    raw=match.group(0)
                )
        except Exception as e:
            print(f"Error parsing {elem_type}: {e}")
            return None

        return None

    def analyze(self):
        """Analyze the document structure"""
        self.load()
        self.parse_header()
        self.parse_elements()

    def generate_report(self) -> str:
        """Generate a comprehensive analysis report"""
        lines = []
        lines.append("=" * 80)
        lines.append("DATAWIN REPORT FORMAT ANALYSIS")
        lines.append("=" * 80)

        lines.append(f"\n[DOCUMENT INFO]")
        lines.append(f"  Magic: {self.document.magic}")
        lines.append(f"  Title: {self.document.title}")
        lines.append(f"  Version Info: {self.document.version_info}")

        # Count elements by type
        type_counts = {}
        for elem in self.document.elements:
            type_counts[elem.element_type] = type_counts.get(elem.element_type, 0) + 1

        lines.append(f"\n[ELEMENT STATISTICS]")
        for elem_type, count in sorted(type_counts.items()):
            lines.append(f"  {elem_type}: {count}")

        # Analyze style flags usage
        lines.append(f"\n[STYLE FLAGS ANALYSIS]")
        style_usage = {}
        for elem in self.document.elements:
            if elem.style_flags:
                for flag in elem.style_flags.split('|'):
                    flag = flag.strip()
                    style_usage[flag] = style_usage.get(flag, 0) + 1

        for flag, count in sorted(style_usage.items(), key=lambda x: -x[1]):
            lines.append(f"  {flag}: {count} occurrences")

        # Coordinate system analysis
        lines.append(f"\n[COORDINATE SYSTEM ANALYSIS]")
        x_vals = [e.x for e in self.document.elements if hasattr(e, 'x') and e.x > 0]
        y_vals = [e.y for e in self.document.elements if hasattr(e, 'y') and e.y > 0]
        w_vals = [e.width for e in self.document.elements if hasattr(e, 'width') and e.width > 0]
        h_vals = [e.height for e in self.document.elements if hasattr(e, 'height') and e.height > 0]

        if x_vals:
            lines.append(f"  X range: {min(x_vals)} - {max(x_vals)}")
        if y_vals:
            lines.append(f"  Y range: {min(y_vals)} - {max(y_vals)}")
        if w_vals:
            lines.append(f"  Width range: {min(w_vals)} - {max(w_vals)}")
        if h_vals:
            lines.append(f"  Height range: {min(h_vals)} - {max(h_vals)}")

        # Font analysis
        lines.append(f"\n[FONT DEFINITIONS]")
        for elem in self.document.elements:
            if isinstance(elem, FontElement):
                lines.append(f"  Name: '{elem.font_name}', Size: {elem.font_size}, Style: {elem.font_style}")

        # Sample elements
        lines.append(f"\n[SAMPLE ELEMENTS (first 20)]")
        for i, elem in enumerate(self.document.elements[:20]):
            lines.append(f"\n  [{i}] {elem.element_type}")
            if isinstance(elem, LabelElement):
                lines.append(f"      Text: \"{elem.text}\"")
            if hasattr(elem, 'x') and elem.x is not None:
                lines.append(f"      Position: ({elem.x}, {elem.y}) Size: {elem.width}x{elem.height}")
            if elem.style_flags:
                lines.append(f"      Style: {elem.style_flags}")

        # DSL Grammar summary
        lines.append(f"\n" + "=" * 80)
        lines.append("DISCOVERED DSL GRAMMAR")
        lines.append("=" * 80)
        lines.append("""
FILE STRUCTURE:
    [Binary Header] (0x00 - 0x2B9)
        - Magic: "Datawin Report." (16 bytes at 0x00)
        - Version/Config data (at 0x20)
        - Report Title (at 0x48, null-terminated, 256 bytes max)
    [DSL Text Content] (0x2BA onwards)
        - HEAD declaration
        - PLANK containers with nested elements
        - Element definitions

ELEMENT SYNTAX:

1. HEAD - Report header definition
   HEAD <height>, <style_flags>
   Example: HEAD 60, PS_BORDER|PS_SHADOW

2. PLANK - Container/Panel element (groups related elements)
   PLANK ID_PLANK+ <id>, <style_flags>, <x>, <y>, <width>, <height>
   Example: PLANK ID_PLANK+ 4, PS_LEFT, 460, 0, 174, 90

3. LABEL - Static text label
   LABEL "<text>", ID_LABEL+ <id>, <style_flags>, <x>, <y>, <width>, <height>
   Example: LABEL "Date : ", ID_LABEL+ 0, PS_LEFT, 0, 0, 42, 15

4. EDIT - Editable field (data placeholder)
   EDIT ID_EDIT+ <id>, <style_flags>, <x>, <y>, <width>, <height>
   Example: EDIT ID_EDIT+ 1, PS_LEFT, 42, 0, 78, 15

5. LINE - Horizontal/Vertical line
   LINE, <thickness>, <x1>, <y1>, <x2>, <y2>
   Example: LINE, 7, 0, 0, 900, 0

6. IMAGE - External image reference
   IMAGE "<path>", ID_LABEL+ <id>, <style_flags>
   Example: IMAGE "C:\\temp\\logo.jpg", ID_LABEL+ 0, PS_LEFT

7. FONT - Font definition (applies to following text elements)
   FONT "<name>", <size>, <style_flags>
   Example: FONT "", 24, PS_FONT_BOLD|PS_FONT_UNDERLINE

STYLE FLAGS:
    PS_LEFT          - Left alignment
    PS_RIGHT         - Right alignment
    PS_CENTER        - Center alignment
    PS_BORDER        - Draw border
    PS_SHADOW        - Add shadow effect
    PS_FONT_BOLD     - Bold font
    PS_FONT_UNDERLINE - Underlined font
    PS_RESERVED3     - Reserved/special flag

COORDINATE SYSTEM:
    - Origin: Top-left corner
    - Units: Likely pixels or points (need verification)
    - All coordinates are relative to parent PLANK container

RENDERING ORDER:
    1. Parse HEAD to get page header height
    2. Process PLANKs in order (containers define regions)
    3. For each PLANK, render child elements in sequence
    4. FONT definitions affect subsequent text elements until changed
    5. EDIT fields are placeholders filled with runtime data
""")

        return '\n'.join(lines)


def main():
    TEMPLATE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"

    parser = ReportParser(TEMPLATE_PATH)
    parser.analyze()

    report = parser.generate_report()
    print(report)

    # Save detailed analysis
    output_path = r"C:\真桌面\Claude code\ERP explore\reverse_engineering\report_format_analysis.txt"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n\nFull analysis saved to: {output_path}")

if __name__ == "__main__":
    main()
