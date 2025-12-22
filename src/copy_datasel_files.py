import shutil
import os

# 原始檔案路徑
source_dir = r"\\192.168.252.16\datawin\EXE"
dest_dir = r"C:\真桌面\Claude code\ERP explore"

files_to_copy = [
    "DataSel.exe",
    "DATASEL.a01",
    "DATASEL.flt"
]

print("開始複製檔案到本地目錄...")
print(f"目標目錄: {dest_dir}\n")

for filename in files_to_copy:
    source_path = os.path.join(source_dir, filename)
    dest_path = os.path.join(dest_dir, f"{os.path.splitext(filename)[0]}_copy{os.path.splitext(filename)[1]}")

    if os.path.exists(source_path):
        try:
            shutil.copy2(source_path, dest_path)
            size = os.path.getsize(dest_path)
            print(f"[OK] 已複製: {filename} -> {os.path.basename(dest_path)} ({size:,} bytes)")
        except Exception as e:
            print(f"[ERROR] 複製失敗: {filename} - {e}")
    else:
        print(f"[ERROR] 檔案不存在: {source_path}")

print("\n複製完成！")
