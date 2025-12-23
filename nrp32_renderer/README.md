# NRP32 Native PDF Renderer

使用 nrp32 的原生 DLL 直接渲染 PDF，速度比 GUI 快 100 倍以上。

## 系統需求

1. **32-bit Python** (因為 WNrpDll.dll 是 32-bit)
2. **Microsoft Print to PDF** (Windows 10/11 內建)
3. **WNrpDll.dll** (來自 DataWin ERP)

## 安裝步驟

### 1. 安裝 32-bit Python

1. 前往 https://www.python.org/downloads/
2. 下載最新版 Python
3. **重要**: 選擇 **Windows installer (32-bit)**
4. 安裝時勾選 "Add Python to PATH"
5. 安裝到自訂路徑，例如 `C:\Python312-32`

### 2. 設置環境

```batch
cd nrp32_renderer
setup_env.bat
```

這會：
- 檢查 32-bit Python
- 創建虛擬環境 (.venv32)
- 安裝 pywin32

### 3. 複製 DLL

確保 `WNrpDll.dll` 在以下位置之一：
- `../nrp_backup/WNrpDll.dll`
- 當前目錄
- `C:\DataWin\`

## 使用方法

### 快速渲染

```batch
render.bat input.tmp output.pdf
```

### Python 腳本

```batch
.venv32\Scripts\activate.bat
python nrp32_renderer.py input.tmp output.pdf
```

### 其他格式

```batch
python nrp32_renderer.py input.tmp --rtf output.rtf
python nrp32_renderer.py input.tmp --txt output.txt
```

### 查看 DLL 資訊

```batch
python nrp32_renderer.py --info
```

## 工作原理

1. 使用 ctypes 調用 WNrpDll.dll 的 CRptDoc 類別
2. `CRptDoc::Read()` 載入 .tmp 檔案
3. `CRptDoc::ShowPage()` 渲染到 Windows DC
4. 輸出到 "Microsoft Print to PDF" 虛擬印表機

## 效能比較

| 方法 | 時間 | 品質 |
|------|------|------|
| nrp32.exe GUI | 30-60 秒 | 完美 |
| **此方案 (DLL)** | **< 1 秒** | **完美** |
| PyMuPDF 自製渲染 | 0.2 秒 | 有差異 |

## 疑難排解

### "This module requires 32-bit Python"
確認使用的是 32-bit Python:
```batch
python -c "import struct; print(struct.calcsize('P')*8, 'bit')"
```
應該顯示 "32 bit"

### "WNrpDll.dll not found"
確認 DLL 路徑正確，或將 DLL 複製到腳本目錄

### "Failed to load DLL"
可能缺少 DLL 依賴，確保以下 DLL 都在:
- WNrpDll.dll
- NrpDll.dll
- MakeReport.dll

## 技術細節

- DLL 使用 Borland C++ Builder 編譯
- 函數名稱使用 Borland 命名修飾 (name mangling)
- 例如: `@CRptDoc@Read$qpxc` = `CRptDoc::Read(const char*)`
