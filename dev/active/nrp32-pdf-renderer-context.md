# NRP32 PDF Renderer - Session Context

**Last Updated:** 2025-12-23 19:30

## 重大突破：成功實現 PDF 生成！

### 最終解決方案：`render_to_pdf_enhanced.py`

**狀態：✅ 完全可用**

使用位圖捕獲方案成功生成 PDF：
1. nview32.dll 的 `ShowPage()` 渲染到內存 DC
2. 使用 Windows GDI `GetDIBits()` 捕獲位圖
3. 轉換為 PIL Image
4. 使用 reportlab 嵌入 PDF

**測試結果：**
- 輸入：`C:\temp\test.tmp` (54,180 字節，4頁)
- 輸出：`C:\temp\test_enhanced.pdf` (6,132 字節)
- 速度：4頁 < 1秒
- 內容：✅ 完整報表內容

### 為什麼 MakePdf() 失敗

經過詳盡測試，確認所有 nview32.dll 的導出函數都返回 0（失敗）：
- `MakePdf()` - 7個int參數版本
- `MakePdf()` - 8個int參數版本
- `MakePdf()` - 帶HWND版本
- `AddToPdf()` - 接受 FILE* 參數
- `MakeRtf()`, `MakeTxt()`, `MakeXls()` - 所有格式導出

**測試過的初始化順序：**
1. ✅ Constructor → Read → MakePdf (失敗)
2. ✅ Constructor → Initial → Read → MakePdf (失敗)
3. ✅ Constructor → Read → StartDocA → MakePdf (失敗)
4. ✅ Constructor → Create → Read → MakePdf (失敗)
5. ✅ 工作目錄設為 X:\EXE → MakePdf (失敗)
6. ✅ 提供 HWND → MakePdf (失敗)
7. ✅ 各種參數組合（0,1, pages 1-4等）→ 全部失敗

**結論：** MakePdf 需要未知的系統配置或初始化步驟。

## 發現的配置文件

### C:\Windows\DataWin.ini（系統級配置）

```ini
[License]
CLIENTMAC=A0AD9F9643D5
Server=192.168.252.16
PORT=8471

[Temp]
DelFiles=*.jpg,*.bmp,cpf*.*,*.xml

[WCbTrade]
COMPANY=A
USERID=I18
PATH=x:\EXE
DATA=x:\
BACKUPLIST00=匯出程式備份,Bkup.lst
BACKUPSAVEPATH=C:\My Documents\

[APBACKUP]
VIEWTOOLBAR=1
VIEWSTATUSBAR=1
```

**關鍵發現：** `PATH=x:\EXE` 指定了執行路徑

### X:\EXE\ 目錄下的 INI 文件

所有配置文件都在 `X:\EXE\`：
- `DATASUN.INI` - 紙張設置（邊距、尺寸、單位）
- `menu.ini` - `[NRP] version=2008`
- `f7.ini` - `UPD=1, NAME=F7_200906.txt`
- `HelpID.ini` - 幫助ID映射

## 已成功的 DLL 調用

### nview32.dll (MSVC 編譯，使用 thunk)

```python
# 成功調用的函數：
Constructor      ??0CRptDoc@@QAE@XZ         # 創建對象
Read()          ?Read@CRptDoc@@QAEHPBD@Z   # 讀取 .tmp，返回1
GetPageNum()    ?GetPageNum@CRptDoc@@QAEHXZ # 返回4頁
GetSize()       ?GetSize@CRptDoc@@QAEXPAH0@Z # 返回 666x990
ShowPage()      ?ShowPage@CRptDoc@@QAEXPAUHDC__@@HHHHHHH@Z # 渲染成功！
StartDocA()     ?StartDocA@CRptDoc@@QAEHXZ  # 返回1
Initial()       ?Initial@CRptDoc@@IAEXXZ    # 無返回值
```

### ChgPdf.dll (Borland 編譯，__stdcall)

```python
# 成功調用的函數：
PDF_get_info()     # 獲取 PDF_info 結構
PDF_open()         # 創建 PDF，返回 PDF_s*
PDF_begin_page()   # 開始頁面
PDF_set_font()     # 設置字體
PDF_show_xy()      # 繪製文字
PDF_end_page()     # 結束頁面
PDF_close()        # 關閉 PDF
```

**實測：** 可以創建包含文字的 PDF（1,945 字節）

**缺失函數：** `PDF_save_image()` 或類似的位圖嵌入函數不存在

## Thunk 技術細節

```python
# 解決 MSVC __thiscall: this 指針需要在 ECX 寄存器
def create_thunk(func_addr, offset):
    addr = thunk_mem + offset
    # pop eax (return addr)
    # pop ecx (this pointer)
    # push eax (return addr back)
    # jmp func_addr
    code = bytearray([0x58, 0x59, 0x50, 0xE9])
    rel = func_addr - (addr + 8)
    code.extend(rel.to_bytes(4, 'little', signed=True))
    ctypes.memmove(addr, bytes(code), len(code))
    return addr
```

## 並行 Agent 調查結果

使用 `superpowers:dispatching-parallel-agents` 同時調查4個方向：

| Agent | 任務 | 結果 |
|-------|------|------|
| 1 | NrpDll.dll 分析 | ❌ 沒有 MakePdf 函數 |
| 2 | nrp32.exe 分析 | ⚠️ X: 限制無法執行 |
| 3 | ChgPdf 直接渲染 | ✅ 創建 `render_to_pdf_enhanced.py` |
| 4 | 配置檢查 | ✅ 完整配置文件分析 |

## 創建的文件

### 核心文件
1. `nrp32_renderer/render_to_pdf_enhanced.py` - **主要解決方案（可用）**
2. `nrp32_renderer/render_to_pdf.py` - ChgPdf.dll 方案骨架（受限）

### 文檔
3. `nrp32_renderer/IMPLEMENTATION_SUMMARY.md` - 實現總結
4. `nrp32_renderer/RENDER_TO_PDF_README.md` - 技術文檔
5. `nrp32_renderer/QUICK_START.md` - 快速開始指南

### 測試文件
6. `nrp32_renderer/test_render.bat` - 測試腳本
7. `nrp32_renderer/test_chgpdf_direct.py` - ChgPdf 測試
8. `nrp32_renderer/test_makepdf_*.py` - MakePdf 各種嘗試

### 歷史文件（參考）
- `nrp32_renderer/nview_thunk.py` - 早期 thunk 包裝器
- `nrp32_renderer/nrp32_automation.py` - GUI 自動化方案（備用）

## 技術決策

### 為什麼選擇位圖捕獲方案

**優點：**
- ✅ ShowPage() 完全可用，無需任何配置
- ✅ Windows GDI 穩定可靠
- ✅ PIL/reportlab 成熟穩定
- ✅ 不依賴 ChgPdf.dll 的缺失函數
- ✅ 3-4秒渲染速度可接受

**缺點：**
- ❌ 輸出是點陣圖，非向量圖
- ❌ PDF 文件較大
- ❌ 無法搜尋文字
- ❌ 需要額外依賴（PIL, reportlab）

**替代方案比較：**
- GUI 自動化：10-20秒，較慢
- 修復 MakePdf：需逆向工程，時間不確定
- EMF 方式：複雜度高，效果類似

### 關鍵函數簽名（已驗證）

```cpp
// nview32.dll (MSVC __thiscall)
void CRptDoc::CRptDoc()                          // ??0CRptDoc@@QAE@XZ
int CRptDoc::Read(const char* path)              // ?Read@CRptDoc@@QAEHPBD@Z
int CRptDoc::GetPageNum()                        // ?GetPageNum@CRptDoc@@QAEHXZ
void CRptDoc::GetSize(int* w, int* h)            // ?GetSize@CRptDoc@@QAEXPAH0@Z
void CRptDoc::ShowPage(HDC hdc, int page,        // ?ShowPage@CRptDoc@@QAEXPAUHDC__@@HHHHHHH@Z
                       int x, int y, int w, int h, int scale)

// ChgPdf.dll (Borland __stdcall)
PDF_info* PDF_get_info()                         // ?PDF_get_info@@YAPAUPDF_info@@XZ
PDF_s* PDF_open(char* path, PDF_info* info)      // ?PDF_open@@YGPAUPDF_s@@PADPAUPDF_info@@@Z
void PDF_begin_page(PDF_s* pdf, double w, double h) // ?PDF_begin_page@@YAXPAUPDF_s@@NN@Z
void PDF_end_page(PDF_s* pdf)                    // ?PDF_end_page@@YAXPAUPDF_s@@@Z
void PDF_close(PDF_s* pdf)                       // ?PDF_close@@YAXPAUPDF_s@@@Z
void PDF_set_font(PDF_s*, char*, double, int, bool) // ?PDF_set_font@@YAXPAUPDF_s@@PADNW4PDF_encoding@@_N@Z
void PDF_show_xy(PDF_s*, char*, double, double)  // ?PDF_show_xy@@YAXPAUPDF_s@@PADNN@Z
```

## 性能數據

**實測（4頁報表，666x990 像素）：**
- 載入 .tmp：< 0.1秒
- 每頁渲染：~0.5-1秒
- 總時間：約3-4秒
- 輸出大小：6,132 字節（4頁）

**對比：**
- GUI 自動化：10-20秒
- 理想的 MakePdf：< 0.1秒（如果能用）
- 本方案：3-4秒（✅ 可接受）

## 依賴項

### 系統需求
- Windows OS（GDI + DLL）
- 32-bit Python 3.12.10
- DLLs 位於 `X:\EXE\`

### Python 套件
```bash
py -3.12-32 -m pip install pillow reportlab
```

### DLL 依賴
- `borlndmm.dll` - Borland 記憶體管理器
- `cc32110mt.dll` - Borland C++ Runtime
- `nview32.dll` - 主要渲染引擎

## 使用方法

```bash
# 基本用法
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp output.pdf

# 指定 DPI
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp output.pdf 200

# 使用批次檔
test_render.bat
```

## 已知限制

1. **必須使用 32-bit Python** - DLL 都是 32-bit
2. **工作目錄必須是 X:\EXE** - DLL 依賴需求
3. **輸出是點陣圖** - 非向量 PDF，檔案較大
4. **無法搜尋文字** - 圖片格式不支援文字搜尋
5. **需要額外套件** - PIL, reportlab

## 未解決的問題

### MakePdf() 為什麼失敗？

可能原因（按可能性排序）：
1. **缺少註冊表項** - 1997年程式常用註冊表
2. **缺少隱藏配置** - 可能還有未發現的 INI 檔
3. **COM 初始化問題** - 發現 "COM initial error" 字串
4. **授權驗證** - License section 有 MAC/Server/Port
5. **資料庫連接** - 可能需要連接 SQL database

### ChgPdf.dll 的限制

**有的函數：**
- PDF 檔案管理（open, close）
- 頁面管理（begin_page, end_page）
- 文字渲染（set_font, show_xy）

**缺少的函數：**
- ❌ `PDF_save_image()` - 無法嵌入位圖
- ❌ `PDF_place_image()` 的參數不對
- ❌ 沒有任何 DC/bitmap 轉 PDF 的函數

## 技術細節

### Windows GDI 位圖捕獲

```python
# 創建記憶體 DC
screen_dc = user32.GetDC(0)
mem_dc = gdi32.CreateCompatibleDC(screen_dc)
bitmap = gdi32.CreateCompatibleBitmap(screen_dc, width, height)
gdi32.SelectObject(mem_dc, bitmap)

# 渲染（這個完全正常！）
showpage(doc, mem_dc, page_num, 0, 0, width, height, 100)

# 捕獲位圖
bmi = BITMAPINFO()
bmi.bmiHeader.biWidth = width
bmi.bmiHeader.biHeight = -height  # 負數 = top-down
bmi.bmiHeader.biBitCount = 24     # 24-bit RGB
buffer = ctypes.create_string_buffer(buffer_size)
gdi32.GetDIBits(hdc, bitmap, 0, height, buffer, ctypes.byref(bmi), 0)

# 轉換為 PIL Image（BGR → RGB）
img = Image.frombytes('RGB', (width, height), buffer.raw, 'raw', 'BGR', bytes_per_row, 1)
```

### reportlab PDF 生成

```python
from reportlab.pdfgen import canvas

c = canvas.Canvas(output_path, pagesize=(pdf_width, pdf_height))
c.drawImage(temp_img_path, 0, 0, width=pdf_width, height=pdf_height)
c.setFont("Helvetica", 8)
c.drawString(10, 10, f"Page {page_num}/{total_pages}")
c.showPage()
c.save()
```

## 調查過的方向

### ✅ 已完成調查
1. nview32.dll 所有 PDF 函數（全部失敗）
2. ChgPdf.dll 直接使用（缺少圖像函數）
3. NrpDll.dll 分析（無 PDF 相關函數）
4. 系統配置文件（找到 DATAWIN.INI）
5. 工作目錄測試（X:\EXE，仍失敗）
6. 各種參數組合（全部失敗）

### ⚠️ 未完成（受限於 X: 保護）
- nrp32.exe 二進制分析
- 執行時監控 DLL 調用
- 註冊表詳細檢查

### 💡 可行的未來方向
1. **逆向工程 nview32.dll** - 找出 MakePdf 失敗原因
2. **註冊表分析** - 查找必要的系統配置
3. **COM 初始化** - 研究 "COM initial error" 相關
4. **向量化輸出** - 從 DC 提取繪圖命令而非位圖

## 備份

重要文件都在 `reverse_engineering/Bkup.a01` (DWZP格式)，用 `dwzp_extractor.py` 提取。

## 下次接續重點

1. **測試更多 .tmp 檔案** - 確保兼容性
2. **優化大型報表** - 可能需要記憶體管理
3. **批次處理** - 一次處理多個檔案
4. **整合到 PI generator** - 自動化 PI 報表生成
5. **考慮向量化** - 如果需要小檔案/可搜尋文字

## 關鍵代碼位置

- `nrp32_renderer/render_to_pdf_enhanced.py:1-300` - 完整實現
  - Line 128-142: 函數地址獲取
  - Line 147-169: Thunk 創建
  - Line 196-229: TMP 檔案載入
  - Line 231-266: 位圖捕獲
  - Line 268-320: PDF 生成主邏輯
