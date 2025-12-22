import struct
import os

def parse_datasel_file(file_path):
    """解析 DATASEL.a01 檔案結構"""

    with open(file_path, 'rb') as f:
        # 讀取檔案頭
        magic = f.read(4)
        print(f"Magic: {magic} ({magic.decode('ascii', errors='ignore')})")

        # 讀取一些可能是檔案元資料的字節
        unknown1 = struct.unpack('<Q', f.read(8))[0]  # 8 bytes
        unknown2 = struct.unpack('<I', f.read(4))[0]  # 4 bytes
        unknown3 = struct.unpack('<I', f.read(4))[0]  # 4 bytes
        filename_len = struct.unpack('<I', f.read(4))[0]  # 4 bytes

        print(f"Unknown1: {unknown1} (0x{unknown1:016x})")
        print(f"Unknown2: {unknown2} (0x{unknown2:08x})")
        print(f"Unknown3: {unknown3} (0x{unknown3:08x})")
        print(f"Filename length: {filename_len}")

        # 讀取檔名
        if filename_len > 0 and filename_len < 256:
            filename = f.read(filename_len).decode('ascii', errors='ignore')
            print(f"Filename: {filename}")

        # 讀取位置
        current_pos = f.tell()
        print(f"\n當前位置: {current_pos} (0x{current_pos:08x})")

        # 讀取接下來的資料
        next_bytes = f.read(100)
        print(f"\n接下來 100 字節:")
        print(f"Hex: {next_bytes.hex()}")

        # 嘗試找尋文字模式
        f.seek(0)
        all_data = f.read()

        print(f"\n\n搜尋可讀文字模式...")

        # 搜尋括號模式 (像是 (Addr), (A1DiSi_tqm01) 等)
        import re

        # 尋找所有 ASCII 可讀的括號內容
        pattern = rb'\([A-Za-z0-9_]+\)'
        matches = re.findall(pattern, all_data)

        if matches:
            print(f"\n找到 {len(matches)} 個可能的 SQL 編號:")
            unique_matches = list(set(matches))
            for i, match in enumerate(unique_matches[:20]):  # 顯示前 20 個
                print(f"  {match.decode('ascii')}")

        # 嘗試找尋中文文字 (Big5 或 UTF-8 編碼)
        print(f"\n\n嘗試提取所有文字內容...")

        # 將資料分成可能的記錄
        # 搜尋模式: (編號) 說明文字
        pattern2 = rb'\(([A-Za-z0-9_]+)\)\s*([^\x00-\x08\x0b-\x1f]*)'
        matches2 = re.findall(pattern2, all_data)

        if matches2:
            print(f"\n找到 {len(matches2)} 筆記錄:")
            sql_records = []

            for code, desc in matches2[:50]:  # 顯示前 50 個
                try:
                    code_str = code.decode('ascii')
                    # 嘗試解碼說明
                    desc_clean = desc.strip()
                    desc_str = ""

                    # 移除無效字符
                    valid_bytes = bytes([b for b in desc_clean if 32 <= b < 127 or b >= 128])

                    if valid_bytes:
                        try:
                            desc_str = valid_bytes.decode('big5', errors='ignore')
                        except:
                            try:
                                desc_str = valid_bytes.decode('utf-8', errors='ignore')
                            except:
                                desc_str = valid_bytes.decode('ascii', errors='ignore')

                    if desc_str:
                        sql_records.append((code_str, desc_str))
                        print(f"  ({code_str}) {desc_str[:80]}")
                except:
                    pass

            return sql_records

        return None

if __name__ == "__main__":
    file_path = r"\\192.168.252.16\datawin\EXE\DATASEL.a01"

    if os.path.exists(file_path):
        print(f"解析檔案: {file_path}\n")
        records = parse_datasel_file(file_path)

        if records:
            # 儲存為 CSV
            import csv
            output_csv = "DATASEL_sql_records.csv"
            with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['SQL編號', '說明'])
                writer.writerows(records)
            print(f"\n\n已儲存 {len(records)} 筆記錄到: {output_csv}")
    else:
        print(f"檔案不存在: {file_path}")
