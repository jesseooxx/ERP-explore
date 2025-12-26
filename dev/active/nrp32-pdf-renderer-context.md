# NRP32 PDF Renderer - Session Context

**Last Updated:** 2025-12-23 19:45

## ⚠️ 重要更正：ShowPage() 渲染失敗

### 實際狀況

經檢查生成的 PDF，發現：
- ❌ **所有 PDF 都是空白或只有占位符**
- ❌ **ShowPage() 雖然調用成功但沒有渲染內容到 DC**
- ❌ **GetPixel 檢查證實：所有像素都是白色**

之前報告的 "SUCCESS" 是誤判 - reportlab 確實創建了 PDF 結構，但圖像內容是空白的。

### 測試過的 ShowPage 版本

```cpp
// 版本1: 簡單版本（HDC, 頁碼）
?ShowPage@CRptDoc@@QAEXPAUHDC__@@H@Z
→ 測試結果：空白

// 版本2: 6參數版本（HDC, 頁碼, x, y, w, h, scale）
?ShowPage@CRptDoc@@QAEXPAUHDC__@@HHHHHH@Z
→ 未測試

// 版本3: 7參數版本（HDC, 頁碼, x, y, w, h, ?, scale）
?ShowPage@CRptDoc@@QAEXPAUHDC__@@HHHHHHH@Z
→ 測試結果：空白

// 持續版本
?ShowPageContinue@CRptDoc@@QAEHPAUHDC__@@HHHHHMM@Z
→ 未測試
```

### 可能需要的初始化函數

發現這些未測試的函數：
- `?setShowEnd@CRptDoc@@QAEXH@Z` - 設置顯示結束標記
- `?SetPrintExtContinue@CRptDoc@@QAEXPAUHDC__@@PAH1HHMM@Z` - 設置列印延續
- `?ShowGroup@CRptDoc@@IAEXPAUHDC__@@PAUtagGroupBlock@@PAX@Z` - 顯示群組

## 已成功的 DLL 調用

### nview32.dll - 基本函數可用

```python
Constructor      ??0CRptDoc@@QAE@XZ         # ✅ 創建對象
Read()          ?Read@CRptDoc@@QAEHPBD@Z   # ✅ 讀取 .tmp，返回1
GetPageNum()    ?GetPageNum@CRptDoc@@QAEHXZ # ✅ 返回4頁
GetSize()       ?GetSize@CRptDoc@@QAEXPAH0@Z # ✅ 返回 666x990
StartDocA()     ?StartDocA@CRptDoc@@QAEHXZ  # ✅ 返回1
ShowPage()      # ❌ 調用成功但無渲染輸出
```

### ChgPdf.dll - 可創建空PDF

```python
PDF_get_info()     # ✅ 獲取 PDF_info 結構
PDF_open()         # ✅ 創建 PDF
PDF_begin_page()   # ✅ 開始頁面
PDF_set_font()     # ✅ 設置字體
PDF_show_xy()      # ✅ 繪製文字（實測可用）
PDF_end_page()     # ✅ 結束頁面
PDF_close()        # ✅ 關閉 PDF
PDF_save_image()   # ❌ 不存在
```

## 所有失敗的功能

### nview32.dll 導出函數
- `MakePdf()` (3個版本) → 返回 0
- `MakeRtf()` → 返回 0
- `MakeTxt()` → 返回 0
- `AddToPdf()` → 返回 0
- `ShowPage()` → **調用成功但無輸出**

### ChgPdf.dll 缺失功能
- 無位圖/圖像嵌入函數

## 發現的配置文件

### C:\Windows\DataWin.ini

```ini
[License]
CLIENTMAC=A0AD9F9643D5
Server=192.168.252.16
PORT=8471

[WCbTrade]
PATH=x:\EXE
DATA=x:\
```

### X:\EXE\ 目錄
- `DATASUN.INI` - 紙張設置
- `menu.ini` - NRP version=2008
- `f7.ini`, `HelpID.ini`

## Thunk 技術（已驗證可用）

```python
def create_thunk(func_addr, offset):
    addr = thunk_mem + offset
    # pop eax, pop ecx, push eax, jmp func_addr
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr
```

**驗證：** thunk 本身工作正常，所有函數都能成功調用並返回預期值。

## 當前狀態

### ❌ 不可用的方案
1. nview32.dll MakePdf - 返回 0
2. nview32.dll ShowPage - 無渲染輸出
3. ChgPdf.dll 直接渲染 - 缺少圖像函數
4. PIL + reportlab 捕獲 - ShowPage 無輸出可捕獲

### ✅ 唯一可用方案
**GUI 自動化：** `nrp32_renderer/nrp32_automation.py`
- 使用 pywinauto 控制 nrp32.exe
- 自動化 Ctrl+P 列印
- 選擇 Microsoft Print to PDF
- 速度：30-60秒/檔案

## 下一步調查方向

### 1. 測試 ShowPageContinue
```cpp
int ShowPageContinue(HDC hdc, int, int, int, int, int, double, double)
```
可能這個才是真正渲染的函數。

### 2. 測試 setShowEnd
可能需要先調用 `setShowEnd(1)` 啟用渲染。

### 3. 檢查是否需要可見窗口
ShowPage 可能需要：
- 真實的窗口 DC（非記憶體 DC）
- 可見的窗口（WS_VISIBLE）
- Windows 消息循環

### 4. 逆向工程 nrp32.exe
分析 nrp32.exe 如何調用 ShowPage，確認正確的調用順序和參數。

## 創建的文件（實際狀態）

### 測試文件
1. `test_chgpdf_direct.py` - ✅ ChgPdf 可創建文字 PDF
2. `test_simple_showpage.py` - ❌ ShowPage 無輸出
3. `debug_showpage.py` - 調試腳本
4. `test_makepdf_*.py` - ❌ 所有 MakePdf 測試失敗

### 方案文件（都不完整）
1. `render_to_pdf.py` - 占位符方案
2. `render_to_pdf_enhanced.py` - **空白圖像方案（失敗）**
3. `nrp32_automation.py` - ✅ GUI 自動化（唯一可用）

### 文檔（需更新）
- `IMPLEMENTATION_SUMMARY.md` - 誤報成功
- `RENDER_TO_PDF_README.md` - 誤報成功
- `QUICK_START.md` - 誤報成功

## 技術債務

需要刪除或更正的誤導性文檔：
- [ ] 更正所有聲稱"成功"的文檔
- [ ] 標記 render_to_pdf_enhanced.py 為失敗
- [ ] 說明唯一可用方案是 GUI 自動化

## 關鍵發現

**ShowPage 不渲染的證據：**
```
測試1: ShowPage(doc, window_dc, 1)
  → GetPixel(100, 100) = -0x1 (錯誤)

測試2: StartDocA() + ShowPage(doc, mem_dc, 0)
  → GetPixel(100, 100) = 0xFFFFFF (白色)

測試3: StartDocA() + ShowPage(doc, mem_dc, 1)
  → GetPixel(100, 100) = 0xFFFFFF (白色)

結論：ShowPage 沒有真正繪製內容
```

## 下次接續重點

1. **測試 ShowPageContinue** - 可能這個才是真的渲染函數
2. **測試 setShowEnd(1)** - 可能需要啟用渲染模式
3. **測試可見窗口 + 消息循環** - ShowPage 可能需要 Windows 消息
4. **分析 nrp32.exe** - 找出正確調用方式（需繞過 X: 限制）
5. **接受現實** - 可能只能用 GUI 自動化

## 備份

重要文件都在 `reverse_engineering/Bkup.a01` (DWZP格式)，用 `dwzp_extractor.py` 提取。
