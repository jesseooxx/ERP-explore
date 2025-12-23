"""
Enhanced Datawin Report DSL Parser with hierarchical structure support
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import IntFlag


class PSFlags(IntFlag):
    """Position/Style flags discovered from the report format"""
    PS_LEFT = 0x01
    PS_RIGHT = 0x02
    PS_CENTER = 0x04
    PS_BORDER = 0x08
    PS_SHADOW = 0x10
    PS_FONT_BOLD = 0x20
    PS_FONT_UNDERLINE = 0x40
    PS_RESERVED3 = 0x80
    PS_IMAGE = 0x100


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

    def get_style_flag_value(self) -> int:
        """Parse style flags string to integer value"""
        flags = 0
        if not self.style_flags:
            return flags

        for flag_str in self.style_flags.split('|'):
            flag_str = flag_str.strip()
            if flag_str == 'PS_LEFT':
                flags |= PSFlags.PS_LEFT
            elif flag_str == 'PS_RIGHT':
                flags |= PSFlags.PS_RIGHT
            elif flag_str == 'PS_CENTER':
                flags |= PSFlags.PS_CENTER
            elif flag_str == 'PS_BORDER':
                flags |= PSFlags.PS_BORDER
            elif flag_str == 'PS_SHADOW':
                flags |= PSFlags.PS_SHADOW
            elif flag_str == 'PS_FONT_BOLD':
                flags |= PSFlags.PS_FONT_BOLD
            elif flag_str == 'PS_FONT_UNDERLINE':
                flags |= PSFlags.PS_FONT_UNDERLINE
            elif flag_str == 'PS_RESERVED3':
                flags |= PSFlags.PS_RESERVED3
            elif flag_str == 'PS_IMAGE':
                flags |= PSFlags.PS_IMAGE

        return flags


@dataclass
class LabelElement(ReportElement):
    """Static text label"""
    text: str = ""


@dataclass
class EditElement(ReportElement):
    """Editable field (data placeholder)"""
    bound_data: str = ""  # Filled by DataBinder


@dataclass
class ImageElement(ReportElement):
    """External image reference"""
    image_path: str = ""


@dataclass
class LineElement(ReportElement):
    """Line drawing element"""
    thickness: int = 1
    x2: int = 0
    y2: int = 0


@dataclass
class FontElement(ReportElement):
    """Font definition (affects subsequent text elements)"""
    font_name: str = ""
    font_size: int = 12
    font_style: str = ""


@dataclass
class PlankElement(ReportElement):
    """Container/Panel element - groups related elements"""
    children: List[ReportElement] = field(default_factory=list)


@dataclass
class HeadElement(ReportElement):
    """Page header definition"""
    head_size: int = 0


@dataclass
class ReportDocument:
    """Complete report document with metadata and elements"""
    magic: str = ""
    title: str = ""
    version_info: Dict = field(default_factory=dict)
    elements: List[ReportElement] = field(default_factory=list)

    # Computed properties
    page_width: int = 900  # Default A4-like width
    page_height: int = 1200  # Default height

    def get_planks(self) -> List[PlankElement]:
        """Get all PLANK elements"""
        return [e for e in self.elements if isinstance(e, PlankElement)]

    def get_head(self) -> Optional[HeadElement]:
        """Get HEAD element"""
        for e in self.elements:
            if isinstance(e, HeadElement):
                return e
        return None


class ReportParser:
    """Parser for Datawin Report .tmp files"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.content = b""
        self.text_content = ""
        self.document = ReportDocument()
        self.current_font = FontElement(
            element_type='FONT',
            font_name='',
            font_size=12,
            font_style=''
        )

    def load(self):
        """Load file and extract text content"""
        with open(self.filepath, 'rb') as f:
            self.content = f.read()

        # Find where DSL text starts (after binary header)
        text_start = 0
        for i in range(len(self.content)):
            if self.content[i:i+4] == b'HEAD':
                text_start = i
                break

        self.text_content = self.content[text_start:].decode('ascii', errors='ignore')

    def parse_header(self):
        """Parse the binary header (0x00 - 0x2B9)"""
        if self.content[:14] == b'Datawin Report':
            self.document.magic = "Datawin Report"

        # Parse version info at offset 0x20
        if len(self.content) >= 0x40:
            version_data = struct.unpack('<8I', self.content[0x20:0x40])
            self.document.version_info = {
                'version': version_data[0],
                'plank_count': version_data[1],
                'element_count': version_data[2],
                'param1': version_data[3],
                'param2': version_data[4],
                'param3': version_data[5],
                'param4': version_data[6],
                'param5': version_data[7],
            }

        # Extract title (at offset 0x48, max 256 bytes)
        title_end = self.content.find(b'\x00', 0x48)
        if title_end > 0x48:
            self.document.title = self.content[0x48:title_end].decode('ascii', errors='ignore')

    def parse_elements(self):
        """Parse DSL elements and build hierarchical structure"""

        # Regular expression patterns for each element type
        patterns = {
            'HEAD': r'HEAD\s+(\d+),\s*([^\n]+)',
            'PLANK': r'PLANK\s+ID_PLANK\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LABEL': r'LABEL\s+"([^"]*)",\s*ID_LABEL\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'EDIT': r'EDIT\s+ID_EDIT\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LINE': r'LINE\s*,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'IMAGE': r'IMAGE\s+"([^"]+)"\s*,\s*ID_LABEL\+\s*(\d+),\s*([^,\n]+)',
            'FONT': r'FONT\s+"([^"]*)",\s*(\d+),\s*([^\n]+)',
        }

        # Parse all elements with their positions in the text
        all_elements = []
        for elem_type, pattern in patterns.items():
            for match in re.finditer(pattern, self.text_content):
                elem = self._create_element(elem_type, match)
                if elem:
                    all_elements.append((match.start(), elem))

        # Sort by position to maintain order
        all_elements.sort(key=lambda x: x[0])

        # Build hierarchical structure (assign elements to PLANKs)
        current_plank = None
        for _, elem in all_elements:
            if isinstance(elem, FontElement):
                # Font affects subsequent elements
                self.current_font = elem
                self.document.elements.append(elem)
            elif isinstance(elem, PlankElement):
                # New PLANK container
                current_plank = elem
                self.document.elements.append(elem)
            elif isinstance(elem, HeadElement):
                # HEAD is top-level
                self.document.elements.append(elem)
            else:
                # Regular element - add to current PLANK if exists
                if current_plank is not None:
                    current_plank.children.append(elem)
                else:
                    # No PLANK context, add to document root
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
            print(f"Warning: Error parsing {elem_type}: {e}")
            return None

        return None

    def parse(self) -> ReportDocument:
        """Parse the complete report file"""
        self.load()
        self.parse_header()
        self.parse_elements()
        return self.document
