"""
完全重新分析二進制格式 - 不依賴任何假設
純粹的二進制結構解析
"""

import struct
import sys

TEMPLATE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"

def full_hex_dump(data, max_bytes=4096):
    """完整的十六進制轉儲"""
    print("=" * 70)
    print("完整十六進制轉儲")
    print("=" * 70)

    for offset in range(0, min(len(data), max_bytes), 16):
        # Hex part
        hex_bytes = ' '.join(f'{b:02X}' for b in data[offset:offset+16])

        # ASCII part
        ascii_chars = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[offset:offset+16])

        # Decimal interpretation for first 4 bytes
        if offset % 16 == 0 and offset + 4 <= len(data):
            dword = struct.unpack('<I', data[offset:offset+4])[0]
            word1 = struct.unpack('<H', data[offset:offset+2])[0]
            word2 = struct.unpack('<H', data[offset+2:offset+4])[0]
            dec_info = f"  [{dword:10d}] [{word1:5d},{word2:5d}]"
        else:
            dec_info = ""

        print(f"{offset:08X}  {hex_bytes:<48}  {ascii_chars:<16} {dec_info}")

def analyze_dword_sequences(data):
    """分析 DWORD 序列模式"""
    print("\n" + "=" * 70)
    print("DWORD 序列分析 (前 256 個 DWORD)")
    print("=" * 70)

    for offset in range(0, min(len(data), 1024), 4):
        dword = struct.unpack('<I', data[offset:offset+4])[0]

        # 高亮特殊值
        if dword == 0:
            marker = "NULL"
        elif dword < 256:
            marker = f"BYTE:{dword}"
        elif 500 <= dword <= 1000:
            marker = f"SIZE?"
        elif dword == 0x00010000:
            marker = "VERSION"
        else:
            marker = ""

        if marker or (offset < 0x100):
            print(f"  0x{offset:04X}: 0x{dword:08X} = {dword:10d}  {marker}")

def search_for_structure_markers(data):
    """搜索結構標記"""
    print("\n" + "=" * 70)
    print("搜索結構標記")
    print("=" * 70)

    # 搜索所有 ASCII 字符串
    print("\n所有 ASCII 字符串 (>= 4 字符):")
    print("-" * 70)

    current_string = b""
    string_start = 0

    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current_string:
                string_start = i
            current_string += bytes([byte])
        else:
            if len(current_string) >= 4:
                s = current_string.decode('ascii')
                print(f"  0x{string_start:04X}: \"{s}\"")
            current_string = b""

def analyze_repeating_patterns(data):
    """分析重複模式"""
    print("\n" + "=" * 70)
    print("分析前 1KB 的 DWORD 值分佈")
    print("=" * 70)

    from collections import Counter

    dwords = []
    for i in range(0, min(1024, len(data)), 4):
        if i + 4 <= len(data):
            dwords.append(struct.unpack('<I', data[i:i+4])[0])

    # 統計頻率
    counts = Counter(dwords)

    print("\n最常見的值 (可能是標記或ID):")
    for value, count in counts.most_common(20):
        if count >= 2:
            print(f"  0x{value:08X} ({value:10d}): 出現 {count} 次")

def try_interpret_as_structure(data):
    """嘗試將前 1KB 解釋為結構體數組"""
    print("\n" + "=" * 70)
    print("嘗試解釋為結構體")
    print("=" * 70)

    # 假設：每個元素是 N 字節的結構
    for struct_size in [4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 64]:
        print(f"\n假設結構大小 = {struct_size} bytes:")

        # 讀取前幾個結構
        num_structs = min(10, len(data) // struct_size)

        for i in range(num_structs):
            offset = i * struct_size
            struct_data = data[offset:offset+struct_size]

            # 嘗試不同的解釋
            hex_str = ' '.join(f'{b:02X}' for b in struct_data)

            # 4個DWORD
            if struct_size >= 16:
                dwords = struct.unpack('<4I', struct_data[:16])
                print(f"  [{i}] 0x{offset:04X}: {dwords[0]:8d} {dwords[1]:8d} {dwords[2]:8d} {dwords[3]:8d}")
            else:
                print(f"  [{i}] 0x{offset:04X}: {hex_str}")

        # 檢查是否有明顯的模式
        # 如果這個大小正確，應該會看到規律

def main():
    print("\n" + "=" * 70)
    print("SAMPLE_REPORT.TMP 完全二進制分析")
    print("=" * 70)

    with open(TEMPLATE_PATH, 'rb') as f:
        data = f.read()

    print(f"\n文件大小: {len(data)} bytes")

    # 1. 完整十六進制轉儲前 4KB
    full_hex_dump(data, max_bytes=512)

    # 2. DWORD 序列分析
    analyze_dword_sequences(data)

    # 3. 搜索標記
    search_for_structure_markers(data)

    # 4. 重複模式
    analyze_repeating_patterns(data)

    # 5. 結構體解釋
    try_interpret_as_structure(data)

    print("\n" + "=" * 70)
    print("分析完成")
    print("=" * 70)

if __name__ == "__main__":
    main()
