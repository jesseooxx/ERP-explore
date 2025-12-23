"""
完整解析器 - 包含所有發現的元素類型
包括: HEAD, BODY, PLANK, LABEL, EDIT, LINE, IMAGE, FONT, DTYPE
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from .parser import PSFlags, ReportElement, PlankElement, LabelElement, EditElement, LineElement, ImageElement, FontElement, HeadElement


@dataclass
class BodyElement(ReportElement):
    """BODY 元素 - 定義主內容區域"""
    body_size: int = 0


@dataclass
class DTypeElement(ReportElement):
    """DTYPE 元素 - 數據類型定義"""
    dtype_spec: str = ""


class CompleteReportParser:
    """完整的報表解析器 - 包含所有元素類型"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.content = b""
        self.text_content = ""

    def parse(self):
        """完整解析"""
        with open(self.filepath, 'rb') as f:
            self.content = f.read()

        # 解析頭部
        magic = self.content[:14].decode('ascii', errors='ignore')
        print(f"Magic: {magic}")

        # 版本信息
        version_data = struct.unpack('<8I', self.content[0x20:0x40])
        print(f"版本: 0x{version_data[0]:08X}")
        print(f"PLANK 數: {version_data[1]}")
        print(f"元素數: {version_data[2]}")
        print(f"參數: {version_data[3:]}")

        # 標題
        title_end = self.content.find(b'\x00', 0x48)
        title = self.content[0x48:title_end].decode('ascii', errors='ignore')
        print(f"標題: {title}")

        # DSL 文本
        dsl_start = self.content.find(b'HEAD')
        if dsl_start == -1:
            dsl_start = 0x2BA

        self.text_content = self.content[dsl_start:].decode('ascii', errors='ignore')

        print(f"\nDSL 起始: 0x{dsl_start:04X}")
        print(f"DSL 文本長度: {len(self.text_content)} 字符")

        # 解析所有元素類型
        self._parse_all_elements()

    def _parse_all_elements(self):
        """解析所有元素類型（包含新發現的）"""

        patterns = {
            'HEAD': r'HEAD\s+(\d+),\s*([^\n]+)',
            'BODY': r'BODY\s+(\d+),\s*([^\n]+)',  # 新發現！
            'PLANK': r'PLANK\s+ID_PLANK\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LABEL': r'LABEL\s+"([^"]*)",\s*ID_LABEL\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'EDIT': r'EDIT\s+ID_EDIT\+\s*(\d+),\s*([^,]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'LINE': r'LINE\s*,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
            'IMAGE': r'IMAGE\s+"([^"]+)"\s*,\s*ID_LABEL\+\s*(\d+),\s*([^,\n]+),?\s*(\d+)?,?\s*(\d+)?,?\s*(\d+)?,?\s*(\d+)?',
            'FONT': r'FONT\s+"([^"]*)",\s*(\d+),\s*([^\n]+)',
            'DTYPE': r'DTYPE\s+([^\n]+)',  # 新發現！
        }

        # 統計
        counts = {}
        for elem_type, pattern in patterns.items():
            matches = re.findall(pattern, self.text_content)
            counts[elem_type] = len(matches)

        print(f"\n元素統計:")
        for etype, count in sorted(counts.items()):
            print(f"  {etype:10s}: {count:4d}")

        # 顯示一些關鍵元素
        print(f"\nBODY 元素:")
        for match in re.finditer(patterns['BODY'], self.text_content):
            print(f"  BODY {match.group(1)}, {match.group(2)}")

        # 檢查 DTYPE 和 EDIT 的關聯
        print(f"\nEDIT + DTYPE 配對 (前 10 個):")
        edit_dtype_pattern = r'(EDIT\s+ID_EDIT\+\s*\d+[^\n]+)\n([^\n]*DTYPE[^\n]*)'
        paired = re.findall(edit_dtype_pattern, self.text_content)
        for i, (edit, dtype) in enumerate(paired[:10]):
            print(f"  {edit}")
            print(f"    → {dtype}")


if __name__ == "__main__":
    parser = CompleteReportParser("nrp_backup/sample_report.tmp")
    parser.parse()
