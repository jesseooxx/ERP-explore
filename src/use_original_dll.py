"""
完全不同的方法：直接使用原始 DLL
不重新實現，只是包裝和加速調用
"""

import ctypes
from ctypes import wintypes
import os

# 加載原始 DLL
NVIEW_DLL_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nview32.dll"

class CRptDocWrapper:
    """
    包裝 nview32.dll 的 CRptDoc 類
    使用原始渲染邏輯，100% 正確
    """

    def __init__(self):
        # 加載 DLL
        try:
            self.dll = ctypes.CDLL(NVIEW_DLL_PATH)
            print(f"成功加載: {NVIEW_DLL_PATH}")
        except Exception as e:
            print(f"無法加載 DLL: {e}")
            print("\n原因可能是:")
            print("  1. DLL 不存在")
            print("  2. 缺少依賴的其他 DLL")
            print("  3. 需要在 nrp_backup 目錄運行")
            self.dll = None
            return

        # 嘗試找到 CRptDoc 構造函數
        # C++ mangled name: ??0CRptDoc@@QAE@XZ
        try:
            self.create = self.dll["??0CRptDoc@@QAE@XZ"]
            print("找到 CRptDoc 構造函數")
        except:
            print("找不到構造函數 - 可能需要不同的調用方式")

    def list_exports(self):
        """列出 DLL 的所有導出函數"""
        print("\nDLL 導出函數:")

        # 需要用 pefile 來讀取導出表
        import pefile
        pe = pefile.PE(NVIEW_DLL_PATH)

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8', errors='ignore')
                    print(f"  - {name}")
        pe.close()


def try_direct_dll_usage():
    """嘗試直接使用 DLL"""

    print("=" * 70)
    print("方案: 直接使用原始 nview32.dll")
    print("=" * 70)

    # 檢查 DLL 是否存在
    dll_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nview32.dll"

    if not os.path.exists(dll_path):
        print(f"\nDLL 不存在: {dll_path}")
        print("\n請檢查 nrp_backup 目錄")
        return

    wrapper = CRptDocWrapper()

    if wrapper.dll:
        wrapper.list_exports()

        print("\n" + "=" * 70)
        print("直接調用 DLL 的優勢")
        print("=" * 70)
        print("""
如果成功調用 nview32.dll:
  ✅ 100% 正確的渲染（使用原始代碼）
  ✅ 無需理解座標系統
  ✅ 無需逆向工程
  ✅ 可以批量處理加速

調用方式:
  C++ DLL → Python ctypes → 批量並行處理
""")


def alternative_approach():
    """替代方案：優化 nrp32.exe 調用"""

    print("\n" + "=" * 70)
    print("替代方案：批量並行調用 nrp32.exe")
    print("=" * 70)

    print("""
如果無法直接調用 DLL，可以優化 EXE 調用：

方案 A: 多進程批量處理
-----------------------
```python
from concurrent.futures import ProcessPoolExecutor
import subprocess

def render_one(tmp_file, pdf_file):
    subprocess.run([
        'nrp32.exe',
        '/input', tmp_file,
        '/output', pdf_file,
        '/silent'  # 如果支持靜默模式
    ])

with ProcessPoolExecutor(max_workers=8) as executor:
    results = executor.map(render_one, tmp_files, pdf_files)
```

優勢:
  ✅ 使用原始 nrp32.exe（100% 正確）
  ✅ 並行處理（8 核 = 8 倍速）
  ✅ 無需理解內部邏輯

方案 B: Wine + Docker (跨平台)
------------------------------
如果需要在 Linux/Mac 運行:
```dockerfile
FROM ubuntu:20.04
RUN apt-get install wine
COPY nrp32.exe /app/
CMD wine nrp32.exe
```

方案 C: 優化工作流程
--------------------
  - 預處理: 批量準備所有 .tmp 文件
  - 並行渲染: 同時運行多個 nrp32.exe 實例
  - 後處理: 批量重命名/移動 PDF
""")

    print("\n哪個方案適合你？")


def main():
    print("\n現狀: Python 重實現失敗（座標全錯）")
    print("\n建議: 使用原始組件但優化調用方式\n")

    # 嘗試 DLL 方式
    try_direct_dll_usage()

    # 展示替代方案
    alternative_approach()

    print("\n" + "=" * 70)
    print("總結")
    print("=" * 70)
    print("""
失敗的方法: 重新實現渲染器（座標系統太複雜）

推薦方法:
  1️⃣ 直接調用 nview32.dll（如果可行） - 最佳
  2️⃣ 批量並行調用 nrp32.exe - 簡單有效
  3️⃣ 繼續逆向工程 - 耗時但可學習

你想試哪個？
""")


if __name__ == "__main__":
    main()
