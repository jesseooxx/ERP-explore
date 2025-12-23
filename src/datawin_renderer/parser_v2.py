"""
Enhanced DSL Parser V2 - Correctly handles hierarchical structure with {}
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntFlag


class PSFlags(IntFlag):
    PS_LEFT = 0x01
    PS_RIGHT = 0x02
    PS_CENTER = 0x04
    PS_BORDER = 0x08
    PS_SHADOW = 0x10
    PS_FONT_BOLD = 0x20
    PS_FONT_UNDERLINE = 0x40
    PS_RESERVED3 = 0x80


@dataclass
class ReportElement:
    element_type: str
    id_type: str = ""
    id_num: int = 0
    style_flags: str = ""
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0
    raw: str = ""

    def get_style_flags_int(self) -> int:
        flags = 0
        for flag_str in self.style_flags.split('|'):
            flag_str = flag_str.strip()
            if flag_str == 'PS_LEFT': flags |= PSFlags.PS_LEFT
            elif flag_str == 'PS_RIGHT': flags |= PSFlags.PS_RIGHT
            elif flag_str == 'PS_CENTER': flags |= PSFlags.PS_CENTER
            elif flag_str == 'PS_BORDER': flags |= PSFlags.PS_BORDER
            elif flag_str == 'PS_SHADOW': flags |= PSFlags.PS_SHADOW
            elif flag_str == 'PS_FONT_BOLD': flags |= PSFlags.PS_FONT_BOLD
            elif flag_str == 'PS_FONT_UNDERLINE': flags |= PSFlags.PS_FONT_UNDERLINE
            elif flag_str == 'PS_RESERVED3': flags |= PSFlags.PS_RESERVED3
        return flags


@dataclass
class LabelElement(ReportElement):
    text: str = ""


@dataclass
class EditElement(ReportElement):
    bound_data: str = ""


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
    children: List[ReportElement] = field(default_factory=list)


@dataclass
class HeadElement(ReportElement):
    head_size: int = 0
    children: List[ReportElement] = field(default_factory=list)


@dataclass
class ReportDocument:
    magic: str = ""
    title: str = ""
    version_info: Dict = field(default_factory=dict)
    head: Optional[HeadElement] = None
    page_width: int = 900
    page_height: int = 1200


class HierarchicalDSLParser:
    """Parser that correctly handles hierarchical {} structure"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.content = b""
        self.text_content = ""
        self.document = ReportDocument()
        self.pos = 0  # Current parsing position

    def load(self):
        with open(self.filepath, 'rb') as f:
            self.content = f.read()

        # Find DSL text start
        text_start = self.content.find(b'HEAD')
        if text_start == -1:
            raise ValueError("Invalid report file: HEAD not found")

        self.text_content = self.content[text_start:].decode('ascii', errors='ignore')

    def parse_header(self):
        if self.content[:14] == b'Datawin Report':
            self.document.magic = "Datawin Report"

        if len(self.content) >= 0x40:
            version_data = struct.unpack('<8I', self.content[0x20:0x40])
            self.document.version_info = {
                'version': version_data[0],
                'plank_count': version_data[1],
                'element_count': version_data[2],
            }

        title_end = self.content.find(b'\x00', 0x48)
        if title_end > 0x48:
            self.document.title = self.content[0x48:title_end].decode('ascii', errors='ignore')

    def skip_whitespace(self):
        while self.pos < len(self.text_content) and self.text_content[self.pos] in ' \t\n\r':
            self.pos += 1

    def parse_element(self) -> Optional[ReportElement]:
        self.skip_whitespace()
        if self.pos >= len(self.text_content):
            return None

        line_start = self.pos
        line_end = self.text_content.find('\n', self.pos)
        if line_end == -1:
            line_end = len(self.text_content)

        line = self.text_content[line_start:line_end].strip()

        # Parse different element types
        if line.startswith('HEAD'):
            return self.parse_head(line)
        elif line.startswith('PLANK'):
            return self.parse_plank(line)
        elif line.startswith('LABEL'):
            return self.parse_label(line)
        elif line.startswith('EDIT'):
            return self.parse_edit(line)
        elif line.startswith('LINE'):
            return self.parse_line(line)
        elif line.startswith('IMAGE'):
            return self.parse_image(line)
        elif line.startswith('FONT'):
            return self.parse_font(line)
        elif line == '{' or line == '}':
            self.pos = line_end + 1
            return None
        else:
            self.pos = line_end + 1
            return None

    def parse_head(self, line: str) -> HeadElement:
        match = re.match(r'HEAD\s+(\d+),\s*(.+)', line)
        if match:
            elem = HeadElement(
                element_type='HEAD',
                head_size=int(match.group(1)),
                style_flags=match.group(2).strip()
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_plank(self, line: str) -> PlankElement:
        match = re.match(r'PLANK\s+ID_PLANK\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)', line)
        if match:
            elem = PlankElement(
                element_type='PLANK',
                id_type='ID_PLANK',
                id_num=int(match.group(1)),
                style_flags=match.group(2).strip(),
                x=int(match.group(3)),
                y=int(match.group(4)),
                width=int(match.group(5)),
                height=int(match.group(6))
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_label(self, line: str) -> LabelElement:
        match = re.match(r'LABEL\s+"([^"]*)",\s*ID_LABEL\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)', line)
        if match:
            elem = LabelElement(
                element_type='LABEL',
                text=match.group(1),
                id_type='ID_LABEL',
                id_num=int(match.group(2)),
                style_flags=match.group(3).strip(),
                x=int(match.group(4)),
                y=int(match.group(5)),
                width=int(match.group(6)),
                height=int(match.group(7))
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_edit(self, line: str) -> EditElement:
        match = re.match(r'EDIT\s+ID_EDIT\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)', line)
        if match:
            elem = EditElement(
                element_type='EDIT',
                id_type='ID_EDIT',
                id_num=int(match.group(1)),
                style_flags=match.group(2).strip(),
                x=int(match.group(3)),
                y=int(match.group(4)),
                width=int(match.group(5)),
                height=int(match.group(6))
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_line(self, line: str) -> LineElement:
        match = re.match(r'LINE\s*,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)', line)
        if match:
            elem = LineElement(
                element_type='LINE',
                thickness=int(match.group(1)),
                x=int(match.group(2)),
                y=int(match.group(3)),
                x2=int(match.group(4)),
                y2=int(match.group(5))
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_image(self, line: str) -> ImageElement:
        match = re.match(r'IMAGE\s+"([^"]+)"\s*,\s*ID_LABEL\+\s*(\d+),\s*([^,\n]+)', line)
        if match:
            elem = ImageElement(
                element_type='IMAGE',
                image_path=match.group(1),
                id_type='ID_LABEL',
                id_num=int(match.group(2)),
                style_flags=match.group(3).strip()
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_font(self, line: str) -> FontElement:
        match = re.match(r'FONT\s+"([^"]*)",\s*(\d+),\s*(.+)', line)
        if match:
            elem = FontElement(
                element_type='FONT',
                font_name=match.group(1),
                font_size=int(match.group(2)),
                font_style=match.group(3).strip()
            )
            self.pos = self.text_content.find('\n', self.pos) + 1
            return elem
        return None

    def parse_children(self) -> List[ReportElement]:
        """Parse children within {} block"""
        children = []

        # Find opening {
        self.skip_whitespace()
        if self.pos < len(self.text_content) and self.text_content[self.pos] == '{':
            self.pos += 1

            while True:
                self.skip_whitespace()
                if self.pos >= len(self.text_content):
                    break

                # Check for closing }
                if self.text_content[self.pos] == '}':
                    self.pos += 1
                    break

                # Parse child element
                elem = self.parse_element()
                if elem:
                    # Check if this element has children
                    saved_pos = self.pos
                    self.skip_whitespace()
                    if self.pos < len(self.text_content) and self.text_content[self.pos] == '{':
                        if hasattr(elem, 'children'):
                            elem.children = self.parse_children()
                    children.append(elem)

        return children

    def parse(self) -> ReportDocument:
        self.load()
        self.parse_header()

        # Parse HEAD and its children
        elem = self.parse_element()
        if elem and isinstance(elem, HeadElement):
            elem.children = self.parse_children()
            self.document.head = elem

        return self.document
