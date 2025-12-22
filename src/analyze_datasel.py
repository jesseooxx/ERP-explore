import struct
import zlib
import os

def analyze_datasel_file(file_path):
    """分析 DATASEL.a01 檔案格式"""

    with open(file_path, 'rb') as f:
        # 讀取檔案頭
        header = f.read(4)
        print(f"檔案頭: {header}")
        print(f"檔案頭 (hex): {header.hex()}")
        print(f"檔案頭 (ASCII): {header.decode('ascii', errors='ignore')}")

        # 讀取接下來的一些字節來分析結構
        f.seek(0)
        first_100_bytes = f.read(100)
        print(f"\n前 100 字節 (hex):\n{first_100_bytes.hex()}")

        # 檢查是否為 zlib 壓縮
        f.seek(4)  # 跳過 DWZP 標記
        compressed_data = f.read()

        print(f"\n嘗試 zlib 解壓縮...")
        try:
            decompressed = zlib.decompress(compressed_data)
            print(f"成功! 解壓縮後大小: {len(decompressed)} bytes")

            # 嘗試解碼為文字
            try:
                text = decompressed.decode('utf-8')
                print(f"\nUTF-8 解碼成功!")
                print(f"前 500 字元:\n{text[:500]}")
                return decompressed
            except:
                try:
                    text = decompressed.decode('big5')
                    print(f"\nBig5 解碼成功!")
                    print(f"前 500 字元:\n{text[:500]}")
                    return decompressed
                except:
                    print(f"\n無法解碼為文字,可能是二進位資料")
                    print(f"前 200 字節:\n{decompressed[:200]}")
                    return decompressed
        except Exception as e:
            print(f"zlib 解壓縮失敗: {e}")

        # 嘗試其他壓縮方法
        print(f"\n嘗試其他解壓縮方法...")
        f.seek(4)
        try:
            # 嘗試不同的 zlib 參數
            decompressed = zlib.decompress(compressed_data, -zlib.MAX_WBITS)
            print(f"zlib (raw deflate) 成功! 大小: {len(decompressed)} bytes")
            return decompressed
        except Exception as e:
            print(f"raw deflate 失敗: {e}")

        return None

if __name__ == "__main__":
    file_path = r"\\192.168.252.16\datawin\EXE\DATASEL.a01"

    if os.path.exists(file_path):
        print(f"分析檔案: {file_path}")
        print(f"檔案大小: {os.path.getsize(file_path)} bytes\n")

        data = analyze_datasel_file(file_path)

        if data:
            # 儲存解壓縮後的資料
            output_path = "DATASEL_decompressed.bin"
            with open(output_path, 'wb') as f:
                f.write(data)
            print(f"\n已儲存解壓縮資料到: {output_path}")
    else:
        print(f"檔案不存在: {file_path}")
