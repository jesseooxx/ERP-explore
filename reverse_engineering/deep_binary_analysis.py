"""
深度二進制分析 - 完全解碼 .tmp 格式
不依賴正則表達式，純二進制解析
"""

import struct
import os
from typing import List, Tuple, Optional

TEMPLATE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"

class BinaryReader:
    """二進制讀取器"""
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_bytes(self, n: int) -> bytes:
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result

    def read_u8(self) -> int:
        return struct.unpack('<B', self.read_bytes(1))[0]

    def read_u16(self) -> int:
        return struct.unpack('<H', self.read_bytes(2))[0]

    def read_u32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_i32(self) -> int:
        return struct.unpack('<i', self.read_bytes(4))[0]

    def read_string(self, length: int) -> str:
        return self.read_bytes(length).decode('ascii', errors='ignore').rstrip('\x00')

    def read_cstring(self, max_len: int = 256) -> str:
        """讀取 null-terminated 字符串"""
        start = self.pos
        end = self.data.find(b'\x00', start, start + max_len)
        if end == -1:
            end = start + max_len
        result = self.data[start:end].decode('ascii', errors='ignore')
        self.pos = end + 1
        return result

    def seek(self, pos: int):
        self.pos = pos

    def tell(self) -> int:
        return self.pos

    def remaining(self) -> int:
        return len(self.data) - self.pos


def analyze_binary_header(data: bytes):
    """分析二進制頭部結構"""
    print("=" * 70)
    print("二進制頭部深度分析")
    print("=" * 70)

    reader = BinaryReader(data)

    # Magic (0x00-0x0F)
    magic = reader.read_string(16)
    print(f"\n[0x00] Magic: '{magic}'")

    # 保留區域 (0x10-0x1F)
    reserved1 = reader.read_bytes(16)
    print(f"[0x10] Reserved: {reserved1.hex()[:40]}...")

    # 版本/配置信息 (0x20-0x3F)
    print(f"\n[0x20] 版本/配置信息:")
    version = reader.read_u32()
    plank_count = reader.read_u32()
    elem_count = reader.read_u32()
    param1 = reader.read_u32()
    param2 = reader.read_u32()
    param3 = reader.read_u32()
    param4 = reader.read_u32()
    param5 = reader.read_u32()

    print(f"  0x20: version      = 0x{version:08X} ({version})")
    print(f"  0x24: plank_count  = {plank_count}")
    print(f"  0x28: elem_count   = {elem_count}")
    print(f"  0x2C: param1       = {param1}")
    print(f"  0x30: param2       = {param2}")
    print(f"  0x34: param3       = {param3}")
    print(f"  0x38: param4       = {param4}")
    print(f"  0x3C: param5       = {param5}")

    # 標題 (0x40-0x13F，應該是0x48開始)
    reader.seek(0x40)
    print(f"\n[0x40] 可能的頭部數據:")
    header_data = reader.read_bytes(8)
    print(f"  {header_data.hex()}")

    reader.seek(0x48)
    title = reader.read_cstring(256)
    print(f"\n[0x48] Title: '{title}'")

    # 繼續掃描到 DSL 文本開始
    print(f"\n[掃描 DSL 開始位置]")
    for offset in [0x100, 0x148, 0x200, 0x2BA]:
        reader.seek(offset)
        preview = reader.read_bytes(64)
        print(f"  0x{offset:04X}: {preview[:40]}")
        # 檢查是否包含 "HEAD", "PLANK"
        if b'HEAD' in preview or b'PLANK' in preview:
            print(f"    ^^^ 找到 DSL 起始點！")
            break

    return {
        'magic': magic,
        'version': version,
        'plank_count': plank_count,
        'elem_count': elem_count,
        'title': title,
        'dsl_start': offset
    }


def analyze_dsl_section(data: bytes, start_offset: int):
    """分析 DSL 文本區段"""
    print("\n" + "=" * 70)
    print("DSL 區段分析（二進制視角）")
    print("=" * 70)

    # 顯示 DSL 文本的前 2000 字節
    dsl_data = data[start_offset:start_offset+2000]

    print(f"\nDSL 起始於: 0x{start_offset:04X}")
    print(f"前 2000 字節:")
    print("-" * 70)

    # 轉為文本顯示
    text = dsl_data.decode('ascii', errors='replace')

    # 按行顯示
    lines = text.split('\n')
    for i, line in enumerate(lines[:50]):
        if line.strip():
            print(f"{i:3d}: {line[:70]}")

    # 查找所有元素定義的模式
    print(f"\n" + "=" * 70)
    print("元素定義統計")
    print("=" * 70)

    import re
    full_text = data[start_offset:].decode('ascii', errors='ignore')

    patterns = {
        'HEAD': r'HEAD\s+(\d+)',
        'PLANK': r'PLANK\s+ID_PLANK\+\s*(\d+)',
        'LABEL': r'LABEL\s+"([^"]*)"',
        'EDIT': r'EDIT\s+ID_EDIT\+\s*(\d+)',
        'LINE': r'LINE\s*,\s*(\d+)',
        'IMAGE': r'IMAGE\s+"([^"]+)"',
        'FONT': r'FONT\s+"([^"]*)",\s*(\d+)',
    }

    for elem_type, pattern in patterns.items():
        matches = re.findall(pattern, full_text)
        print(f"{elem_type:10s}: {len(matches):4d} 個")

        # 顯示前幾個樣本
        if matches and elem_type in ['LABEL', 'EDIT']:
            print(f"  樣本: {matches[:5]}")


def analyze_structure_with_markers(data: bytes):
    """使用標記符尋找結構模式"""
    print("\n" + "=" * 70)
    print("結構標記分析")
    print("=" * 70)

    # 尋找重複的 4 字節模式
    dword_count = {}
    for i in range(0, min(len(data), 10000), 4):
        dword = struct.unpack('<I', data[i:i+4])[0]
        dword_count[dword] = dword_count.get(dword, 0) + 1

    # 找出最常見的值
    common_values = sorted(dword_count.items(), key=lambda x: -x[1])[:20]

    print("\n最常見的 DWORD 值（可能是標記符）:")
    for value, count in common_values:
        if count > 10:  # 出現超過10次
            print(f"  0x{value:08X}: {count:4d} 次", end="")
            # 嘗試解釋
            if value == 0:
                print(" (NULL)")
            elif value < 1000:
                print(f" (可能是計數器或ID)")
            else:
                print()


def hex_dump_regions(data: bytes):
    """十六進制轉儲關鍵區域"""
    print("\n" + "=" * 70)
    print("關鍵區域十六進制轉儲")
    print("=" * 70)

    regions = [
        (0x00, 64, "Header Magic"),
        (0x20, 32, "Version Info"),
        (0x48, 64, "Title"),
        (0x2B0, 128, "DSL Start"),
    ]

    for offset, length, desc in regions:
        print(f"\n[0x{offset:04X}] {desc}:")
        chunk = data[offset:offset+length]

        # Hex dump
        for i in range(0, len(chunk), 16):
            hex_part = ' '.join(f'{b:02x}' for b in chunk[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk[i:i+16])
            print(f"  {offset+i:04X}: {hex_part:<48} {ascii_part}")


def main():
    print("\n" + "=" * 70)
    print("SAMPLE_REPORT.TMP 深度二進制分析")
    print("=" * 70)

    with open(TEMPLATE_PATH, 'rb') as f:
        data = f.read()

    print(f"\n文件大小: {len(data)} bytes ({len(data)/1024:.2f} KB)")

    # 分析頭部
    header_info = analyze_binary_header(data)

    # 十六進制轉儲
    hex_dump_regions(data)

    # 分析 DSL 區段
    analyze_dsl_section(data, header_info.get('dsl_start', 0x2BA))

    # 結構標記分析
    analyze_structure_with_markers(data)

    # 保存分析結果
    output_file = "reverse_engineering/deep_binary_analysis.txt"
    print(f"\n分析結果已保存到: {output_file}")


if __name__ == "__main__":
    main()
