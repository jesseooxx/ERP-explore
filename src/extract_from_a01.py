import struct
import re

def extract_readable_text(file_path):
    """從 DATASEL.a01 中提取可讀文字"""

    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"檔案大小: {len(data):,} bytes\n")

    # 分析檔案頭
    magic = data[0:4]
    print(f"Magic: {magic} ({magic.decode('ascii', errors='ignore')})\n")

    # 搜尋所有可能的 SQL 編號模式: (編號)
    print("搜尋 SQL 編號模式 (編號)...")
    print("=" * 60)

    pattern = rb'\([A-Za-z0-9_]{3,50}\)'
    matches = re.findall(pattern, data)

    if matches:
        unique_codes = list(set(matches))
        print(f"找到 {len(unique_codes)} 個不重複的編號:\n")

        sql_codes = []
        for code in sorted(unique_codes):
            code_str = code.decode('ascii')
            sql_codes.append(code_str)
            print(f"  {code_str}")

        # 儲存編號
        with open("sql_codes_from_a01.txt", 'w', encoding='utf-8') as f:
            for code in sorted(sql_codes):
                f.write(code + "\n")

        print(f"\n編號已儲存到: sql_codes_from_a01.txt")

    # 嘗試提取每個編號附近的說明文字
    print(f"\n\n嘗試提取編號和說明...")
    print("=" * 60)

    # 更寬鬆的模式: (編號) 後面跟著任何文字
    pattern2 = rb'\(([A-Za-z0-9_]{3,50})\)([^\x00-\x08\x0b-\x1f]{1,200}?)'

    matches2 = re.findall(pattern2, data)

    if matches2:
        print(f"找到 {len(matches2)} 筆編號-說明配對:\n")

        sql_records = []

        for code, desc_bytes in matches2[:100]:  # 先顯示前 100 筆
            code_str = code.decode('ascii')

            # 嘗試解碼說明
            desc_str = ""

            # 清理描述字節
            desc_clean = bytes([b for b in desc_bytes if 32 <= b < 127 or b >= 160])

            if len(desc_clean) > 0:
                # 嘗試 Big5 編碼
                try:
                    desc_str = desc_clean.decode('big5', errors='ignore').strip()
                except:
                    try:
                        desc_str = desc_clean.decode('utf-8', errors='ignore').strip()
                    except:
                        desc_str = desc_clean.decode('ascii', errors='ignore').strip()

                # 只保留有意義的說明
                if desc_str and len(desc_str) > 1:
                    # 移除尾部的奇怪字元
                    desc_str = desc_str.split('\x00')[0].strip()

                    if desc_str:
                        sql_records.append((code_str, desc_str))
                        print(f"({code_str}) {desc_str[:80]}")

        # 儲存為 CSV
        if sql_records:
            import csv
            with open("sql_records_from_a01.csv", 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['SQL編號', '說明'])
                writer.writerows(sql_records)

            print(f"\n\n已儲存 {len(sql_records)} 筆記錄到: sql_records_from_a01.csv")

if __name__ == "__main__":
    file_path = r"C:\真桌面\Claude code\ERP explore\DATASEL_copy.a01"
    extract_readable_text(file_path)
