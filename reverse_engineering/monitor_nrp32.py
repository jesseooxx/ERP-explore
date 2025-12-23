"""
監控 nrp32.exe 運行時行為
使用 Windows API hooks 或 Process Monitor 方法
"""

import subprocess
import os
import time
from pathlib import Path

def try_run_nrp32_with_file():
    """嘗試用不同方法運行 nrp32.exe"""

    nrp_exe = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"
    tmp_file = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"

    print("=" * 70)
    print("嘗試運行 nrp32.exe")
    print("=" * 70)

    # 方法 1: 直接用文件參數
    print("\n[方法 1] 直接打開 .tmp 文件...")
    try:
        # 嘗試用 nrp32.exe 打開 .tmp
        proc = subprocess.Popen([nrp_exe, tmp_file],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        time.sleep(2)  # 等待啟動
        if proc.poll() is None:
            print("  程序已啟動 (GUI mode)")
            print("  PID:", proc.pid)
            print("  請在 GUI 中查看渲染結果")
            print("  按 Ctrl+C 結束監控...")
            proc.wait(timeout=10)
        else:
            stdout, stderr = proc.communicate()
            print(f"  返回碼: {proc.returncode}")
            if stdout:
                print(f"  輸出: {stdout.decode('gbk', errors='ignore')}")
            if stderr:
                print(f"  錯誤: {stderr.decode('gbk', errors='ignore')}")
    except subprocess.TimeoutExpired:
        print("  GUI 程序仍在運行，手動關閉")
        proc.terminate()
    except Exception as e:
        print(f"  錯誤: {e}")

    # 方法 2: 使用 start 命令
    print("\n[方法 2] 使用 Windows start 命令...")
    try:
        os.system(f'start "" "{nrp_exe}" "{tmp_file}"')
        print("  已啟動 nrp32.exe GUI")
        print("  請手動操作並觀察:")
        print("    1. 文件是否正確加載?")
        print("    2. 如何渲染頁面?")
        print("    3. 座標如何顯示?")
    except Exception as e:
        print(f"  錯誤: {e}")


def analyze_nrp32_strings():
    """分析 nrp32.exe 中的字符串尋找線索"""

    exe_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

    print("\n" + "=" * 70)
    print("分析 nrp32.exe 內部字符串")
    print("=" * 70)

    with open(exe_path, 'rb') as f:
        data = f.read()

    # 尋找關鍵字符串
    keywords = [
        b'coordinate', b'Coordinate',
        b'scale', b'Scale',
        b'point', b'Point',
        b'pixel', b'Pixel',
        b'twip', b'Twip',
        b'0.1', b'0.01',
        b'DPI', b'dpi',
        b'margin', b'Margin',
        b'ShowPage', b'Render',
    ]

    print("\n查找座標相關字符串:")
    for keyword in keywords:
        pos = data.find(keyword)
        if pos != -1:
            # 提取上下文
            start = max(0, pos - 20)
            end = min(len(data), pos + 40)
            context = data[start:end]
            # 顯示
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            print(f"  找到 '{keyword.decode()}' @ 0x{pos:06X}")
            print(f"    上下文: {ascii_str}")


def create_minimal_test_case():
    """創建最小化測試用例"""

    print("\n" + "=" * 70)
    print("創建最小化測試 .tmp 文件")
    print("=" * 70)

    # 創建一個只有1個 LABEL 的最簡單報表
    minimal_tmp = b"Datawin Report.\n"  # Magic
    minimal_tmp += b'\x00' * 16  # Padding
    minimal_tmp += struct.pack('<8I',
        0x00010000,  # version
        1,           # plank_count
        1,           # elem_count
        0, 0, 0, 0, 0
    )
    minimal_tmp += b"MINIMAL TEST"  # Title
    minimal_tmp += b'\x00' * (0x2BA - len(minimal_tmp))  # Pad to DSL start

    # DSL content
    minimal_tmp += b'HEAD 60, PS_BORDER\n'
    minimal_tmp += b'PLANK ID_PLANK+ 0, PS_LEFT, 0, 0, 200, 50\n'
    minimal_tmp += b'LABEL "TEST", ID_LABEL+ 0, PS_LEFT, 10, 10, 100, 20\n'

    output_path = r"C:\真桌面\Claude code\ERP explore\reverse_engineering\minimal_test.tmp"
    with open(output_path, 'wb') as f:
        f.write(minimal_tmp)

    print(f"  創建: {output_path}")
    print(f"  大小: {len(minimal_tmp)} bytes")
    print("\n  內容:")
    print("    - 1 個 PLANK")
    print("    - 1 個 LABEL '​TEST' @ (10, 10)")
    print("\n  用 nrp32.exe 打開此文件，觀察 'TEST' 在哪裡")
    print("  這能幫助理解真實的座標系統！")

    return output_path


import struct

def main():
    print("NRP32.EXE 運行時分析")

    # 分析字符串
    # analyze_nrp32_strings()

    # 創建測試用例
    minimal_path = create_minimal_test_case()

    print("\n" + "=" * 70)
    print("建議的測試步驟")
    print("=" * 70)
    print("\n1. 手動運行:")
    print(f"   nrp32.exe {minimal_path}")
    print("\n2. 觀察 'TEST' 文字出現在:")
    print("   - 左上角?")
    print("   - 中央?")
    print("   - 座標 (10, 10) 的位置?")
    print("\n3. 測量位置 (用像素或毫米)")
    print("\n4. 回報結果，我將據此修正座標計算")

    # 可選：嘗試自動運行
    print("\n" + "=" * 70)
    print("自動測試 (可選)")
    print("=" * 70)
    print("\n按 Enter 嘗試自動運行 nrp32.exe...")
    print("或 Ctrl+C 跳過...")

    try:
        input()
        try_run_nrp32_with_file()
    except KeyboardInterrupt:
        print("\n跳過自動運行")


if __name__ == "__main__":
    main()
