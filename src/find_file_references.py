import re

def find_file_references(exe_path):
    """在 EXE 中搜尋檔案相關的引用"""

    with open(exe_path, 'rb') as f:
        data = f.read()

    print("搜尋檔案引用...")
    print("=" * 60)

    # 搜尋模式
    patterns = {
        '.a01 檔案': rb'[A-Za-z0-9_]+\.a01',
        '.flt 檔案': rb'[A-Za-z0-9_]+\.flt',
        'DWZP': rb'DWZP.{0,50}',
        'Init_dsfieldinf': rb'Init_dsfieldinf[^\x00]{0,50}',
        '檔案操作API': rb'(CreateFile|ReadFile|OpenFile|GetFile)[A-Za-z]*',
    }

    for name, pattern in patterns.items():
        print(f"\n搜尋: {name}")
        print("-" * 60)
        matches = re.findall(pattern, data, re.IGNORECASE)

        if matches:
            unique = list(set(matches))
            print(f"找到 {len(unique)} 個匹配:")
            for match in unique[:20]:
                try:
                    # 嘗試解碼
                    decoded = match.decode('ascii', errors='ignore')
                    # 清除控制字元
                    cleaned = ''.join(c if 32 <= ord(c) < 127 else '.' for c in decoded)
                    print(f"  {cleaned}")
                except:
                    print(f"  {match.hex()}")
        else:
            print(f"  無匹配")

    # 搜尋可能的解壓縮函數名
    print(f"\n\n搜尋壓縮/解壓縮相關:")
    print("-" * 60)

    compress_keywords = [
        b'compress', b'Compress',
        b'decompress', b'Decompress',
        b'inflate', b'Inflate',
        b'deflate', b'Deflate',
        b'unzip', b'Unzip', b'UnZip',
        b'zlib', b'ZLib',
    ]

    for keyword in compress_keywords:
        # 搜尋前後 30 bytes 的上下文
        pattern = rb'.{0,30}' + re.escape(keyword) + rb'.{0,30}'
        matches = re.findall(pattern, data)

        if matches:
            print(f"\n關鍵字: {keyword.decode('ascii')}")
            for match in matches[:5]:
                try:
                    decoded = match.decode('ascii', errors='ignore')
                    cleaned = ''.join(c if 32 <= ord(c) < 127 else '.' for c in decoded)
                    print(f"  ...{cleaned}...")
                except:
                    pass

if __name__ == "__main__":
    exe_path = r"C:\真桌面\Claude code\ERP explore\DataSel_copy.exe"
    find_file_references(exe_path)
