import os
import re

def extract_strings(file_path, min_length=4):
    """從二進位檔案中提取可讀字串"""

    with open(file_path, 'rb') as f:
        data = f.read()

    # ASCII 字串
    ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)

    # Unicode 字串 (每個字元後跟 \x00)
    unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)

    return ascii_strings, unicode_strings

def analyze_datasel_exe(exe_path):
    """分析 DataSel.exe"""

    print(f"分析: {exe_path}")
    print(f"檔案大小: {os.path.getsize(exe_path)} bytes\n")

    ascii_strings, unicode_strings = extract_strings(exe_path, min_length=5)

    print(f"找到 {len(ascii_strings)} 個 ASCII 字串")
    print(f"找到 {len(unicode_strings)} 個 Unicode 字串\n")

    # 搜尋關鍵字
    keywords = [
        b'DWZP',
        b'.a01',
        b'.flt',
        b'decompress',
        b'decrypt',
        b'zlib',
        b'inflate',
        b'unzip',
        b'compress',
        b'TFileStream',
        b'TMemoryStream',
        b'LoadFromFile',
        b'sql',
        b'query',
        b'select',
    ]

    print("搜尋關鍵字串:")
    print("=" * 60)

    all_strings = ascii_strings + unicode_strings

    for keyword in keywords:
        matches = [s for s in all_strings if keyword.lower() in s.lower()]
        if matches:
            print(f"\n關鍵字: {keyword.decode('ascii', errors='ignore')}")
            for match in matches[:10]:  # 只顯示前 10 個
                try:
                    decoded = match.decode('ascii', errors='ignore')
                    if len(decoded) < 200:  # 只顯示短的字串
                        print(f"  {decoded}")
                except:
                    pass

    # 儲存所有字串到檔案
    output_file = "DataSel_strings.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("ASCII 字串:\n")
        f.write("=" * 60 + "\n\n")
        for s in ascii_strings:
            try:
                decoded = s.decode('ascii', errors='ignore')
                if len(decoded) < 500:
                    f.write(decoded + "\n")
            except:
                pass

        f.write("\n\nUnicode 字串:\n")
        f.write("=" * 60 + "\n\n")
        for s in unicode_strings:
            try:
                # 移除 null bytes
                cleaned = bytes([b for b in s if b != 0])
                decoded = cleaned.decode('ascii', errors='ignore')
                if len(decoded) < 500:
                    f.write(decoded + "\n")
            except:
                pass

    print(f"\n\n所有字串已儲存到: {output_file}")

    # 搜尋可能的函數名稱或 API 調用
    print("\n\n搜尋可能的 Delphi 類別和函數:")
    print("=" * 60)

    delphi_patterns = [
        b'T[A-Z][a-zA-Z0-9]+',  # Delphi 類別名稱
    ]

    for pattern in delphi_patterns:
        matches = re.findall(pattern, b'\n'.join(all_strings))
        unique_matches = list(set(matches))

        print(f"\n找到 {len(unique_matches)} 個 Delphi 類別:")
        for match in sorted(unique_matches)[:30]:
            try:
                print(f"  {match.decode('ascii')}")
            except:
                pass

if __name__ == "__main__":
    # 使用本地複製的檔案
    exe_path = r"C:\真桌面\Claude code\ERP explore\DataSel_copy.exe"

    if os.path.exists(exe_path):
        analyze_datasel_exe(exe_path)
    else:
        print(f"檔案不存在: {exe_path}")
