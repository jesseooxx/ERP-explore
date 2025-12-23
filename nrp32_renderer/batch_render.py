"""
批次處理 TMP 報表轉 PDF

使用方法:
  py -3.12-32 batch_render.py <input_dir> <output_dir> [dpi]

範例:
  py -3.12-32 batch_render.py C:\\temp\\reports C:\\temp\\output 150
"""

import os
import sys
import glob
import time
from pathlib import Path

# 驗證 32-bit Python
import struct
if struct.calcsize("P") * 8 != 32:
    print("錯誤：需要 32-bit Python")
    print("使用：py -3.12-32 batch_render.py ...")
    sys.exit(1)

# 導入渲染器
sys.path.insert(0, os.path.dirname(__file__))
from render_to_pdf_enhanced import EnhancedTmpToPdfRenderer

def batch_render(input_dir, output_dir, dpi=150):
    """批次渲染所有 .tmp 檔案"""

    # 確保輸出目錄存在
    os.makedirs(output_dir, exist_ok=True)

    # 尋找所有 .tmp 檔案
    tmp_files = glob.glob(os.path.join(input_dir, "*.tmp"))
    tmp_files.extend(glob.glob(os.path.join(input_dir, "*.TMP")))
    tmp_files = sorted(set(tmp_files))

    if not tmp_files:
        print(f"錯誤：在 {input_dir} 找不到 .tmp 檔案")
        return 1

    print("=" * 70)
    print(f"批次 TMP → PDF 轉換")
    print("=" * 70)
    print(f"輸入目錄: {input_dir}")
    print(f"輸出目錄: {output_dir}")
    print(f"DPI:      {dpi}")
    print(f"找到:     {len(tmp_files)} 個 .tmp 檔案")
    print("=" * 70)
    print()

    # 統計
    success_count = 0
    fail_count = 0
    total_time = 0
    total_input_size = 0
    total_output_size = 0

    # 處理每個檔案
    for i, tmp_path in enumerate(tmp_files, 1):
        filename = os.path.basename(tmp_path)
        pdf_filename = filename.replace('.tmp', '.pdf').replace('.TMP', '.pdf')
        pdf_path = os.path.join(output_dir, pdf_filename)

        print(f"[{i}/{len(tmp_files)}] {filename}")

        try:
            # 記錄輸入大小
            input_size = os.path.getsize(tmp_path)
            total_input_size += input_size

            # 渲染
            start_time = time.time()
            renderer = EnhancedTmpToPdfRenderer()

            if not renderer.load_tmp(tmp_path):
                print(f"  ❌ 載入失敗")
                fail_count += 1
                continue

            if not renderer.render_to_pdf(pdf_path, dpi):
                print(f"  ❌ 渲染失敗")
                fail_count += 1
                continue

            renderer.cleanup()
            elapsed = time.time() - start_time
            total_time += elapsed

            # 記錄輸出大小
            output_size = os.path.getsize(pdf_path)
            total_output_size += output_size

            print(f"  ✅ 成功 - {output_size:,} bytes, {elapsed:.1f}秒")
            success_count += 1

        except Exception as e:
            print(f"  ❌ 錯誤: {e}")
            fail_count += 1

    # 總結
    print()
    print("=" * 70)
    print("批次處理完成")
    print("=" * 70)
    print(f"成功: {success_count}/{len(tmp_files)}")
    print(f"失敗: {fail_count}/{len(tmp_files)}")
    print(f"總時間: {total_time:.1f} 秒")
    print(f"平均: {total_time/success_count:.1f} 秒/檔案" if success_count > 0 else "")
    print()
    print(f"輸入總大小: {total_input_size:,} bytes ({total_input_size/1024:.1f} KB)")
    print(f"輸出總大小: {total_output_size:,} bytes ({total_output_size/1024:.1f} KB)")
    if total_input_size > 0:
        print(f"壓縮比: {total_output_size/total_input_size*100:.1f}%")
    print("=" * 70)

    return 0 if fail_count == 0 else 1


def main():
    if len(sys.argv) < 3:
        print("批次 TMP 報表轉 PDF")
        print()
        print("使用方法:")
        print("  py -3.12-32 batch_render.py <input_dir> <output_dir> [dpi]")
        print()
        print("範例:")
        print("  py -3.12-32 batch_render.py C:\\temp\\reports C:\\temp\\pdf 150")
        print()
        print("參數:")
        print("  input_dir  - 包含 .tmp 檔案的目錄")
        print("  output_dir - PDF 輸出目錄")
        print("  dpi        - 解析度（選填，預設 150）")
        return 1

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    dpi = int(sys.argv[3]) if len(sys.argv) > 3 else 150

    if not os.path.exists(input_dir):
        print(f"錯誤：輸入目錄不存在: {input_dir}")
        return 1

    return batch_render(input_dir, output_dir, dpi)


if __name__ == '__main__':
    sys.exit(main())
