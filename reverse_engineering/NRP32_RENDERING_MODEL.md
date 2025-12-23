# NRP32.EXE 排版渲染模型完整逆向工程報告

## 概述

nrp32.exe 是 DataWin ERP 系統的報表預覽和打印程序。本文檔記錄了其完整的排版和渲染機制。

## 1. 技術架構

### 1.1 開發框架
- **編譯器**: Borland C++ Builder 4.0
- **框架**: VCL (Visual Component Library)
- **圖形 API**: Windows GDI (32-bit)
- **目標平台**: Windows 32-bit GUI Application

### 1.2 核心組件

| 文件 | 類型 | 功能 |
|------|------|------|
| nrp32.exe | 主程序 | 報表預覽器、打印管理 |
| nview32.dll | 核心庫 | 報表文檔處理和渲染引擎 |
| MakeReport.dll | 報表設計 | 報表模板編輯器組件 |
| MakeForm.dll | 表單設計 | 表單設計器組件 |
| NrpDll.dll | 接口層 | ERP 數據接口 |

### 1.3 關鍵類 (來自 nview32.dll)

```cpp
class CRptDoc {
    // 報表文檔管理
    BOOL Create(DWORD flags, int x, int y, const char* path, const char* title);
    BOOL Read(const char* filePath);
    BOOL SaveFile(const char* filePath);

    // 渲染
    void ShowPage(HDC hdc, int page, int x, int y, int width, int height, int scale, int flags);
    int ShowPageContinue(HDC hdc, int x, int y, int width, int height, float scaleX, float scaleY);

    // 導出
    int MakePdf(const char* path, int dpi, ...);
    int MakeRtf(const char* path, HWND hwnd, int flags);
    int MakeXls(const char* path, HWND hwnd, int flags);
    int MakeTxt(const char* path);

    // 屬性
    int GetPageNum();
    void GetSize(int* width, int* height);
    CRptPage* Get_thePage();
};

class CRptObj {
    // 報表對象基類
    char* GetText();
    char* SetText(const char* text);
};

class CRptPage {
    // 頁面管理
};
```

## 2. 報表文件格式 (.tmp)

### 2.1 文件結構

```
+-------------------+
| Binary Header     | 0x000 - 0x2B9 (698 bytes)
+-------------------+
| DSL Text Content  | 0x2BA onwards
+-------------------+
```

### 2.2 Binary Header 格式

| 偏移 | 大小 | 內容 |
|------|------|------|
| 0x00 | 16 bytes | Magic: "Datawin Report." |
| 0x10 | 16 bytes | 保留 (NULL) |
| 0x20 | 4 bytes | 版本標識 (0x00010000) |
| 0x24 | 4 bytes | PLANK 數量 |
| 0x28 | 4 bytes | 元素總數 |
| 0x2C | 20 bytes | 其他配置參數 |
| 0x48 | 256 bytes | 報表標題 (NULL 結尾) |

### 2.3 DSL (Domain Specific Language) 語法

#### 2.3.1 元素類型

```
HEAD <height>, <style_flags>
```
定義頁面頭部區域的高度和樣式。

```
PLANK ID_PLANK+ <id>, <style_flags>, <x>, <y>, <width>, <height>
```
容器元素，用於分組其他元素。所有子元素座標相對於 PLANK。

```
LABEL "<text>", ID_LABEL+ <id>, <style_flags>, <x>, <y>, <width>, <height>
```
靜態文本標籤。

```
EDIT ID_EDIT+ <id>, <style_flags>, <x>, <y>, <width>, <height>
```
數據綁定字段，運行時填充數據。

```
LINE, <thickness>, <x1>, <y1>, <x2>, <y2>
```
直線繪製。

```
IMAGE "<path>", ID_LABEL+ <id>, <style_flags>
```
外部圖片引用。

```
FONT "<name>", <size>, <style_flags>
```
字體定義，影響後續文本元素。

#### 2.3.2 樣式標誌 (Style Flags)

| 標誌 | 值 | 說明 |
|------|-----|------|
| PS_LEFT | 0x01 | 左對齊 |
| PS_RIGHT | 0x02 | 右對齊 |
| PS_CENTER | 0x04 | 居中對齊 |
| PS_BORDER | 0x08 | 繪製邊框 |
| PS_SHADOW | 0x10 | 添加陰影 |
| PS_FONT_BOLD | 0x20 | 粗體 |
| PS_FONT_UNDERLINE | 0x40 | 下劃線 |
| PS_RESERVED3 | 0x80 | 保留 (圖片容器) |
| PS_IMAGE | -- | 圖片元素 |

#### 2.3.3 範例

```
HEAD 60, PS_BORDER|PS_SHADOW
PLANK ID_PLANK+ 0, PS_LEFT, 0, 0, 900, 45
  EDIT ID_EDIT+ 0, PS_CENTER, 0, 0, 900, 30
  FONT "", 24, PS_FONT_BOLD|PS_FONT_UNDERLINE
PLANK ID_PLANK+ 4, PS_LEFT, 460, 0, 174, 90
  LABEL "Date : ", ID_LABEL+ 0, PS_LEFT, 0, 0, 42, 15
  LABEL "ORDER: ", ID_LABEL+ 1, PS_LEFT, 0, 15, 42, 15
  EDIT ID_EDIT+ 1, PS_LEFT, 42, 0, 78, 15
  EDIT ID_EDIT+ 2, PS_LEFT, 42, 15, 120, 15
PLANK ID_PLANK+ 2, PS_LEFT, 0, 200, 900, 1
  LINE, 7, 0, 0, 900, 0
```

## 3. 座標系統

### 3.1 單位
- 座標單位: **0.1 毫米** (推測) 或 **twips** (1/20 點)
- 基於分析：
  - 頁面寬度 900 = 90mm (A4 約 210mm，這可能是內容區)
  - 常見元素高度 15 = 1.5mm (約一行文字)

### 3.2 座標原點
- 原點位於左上角
- X 軸向右為正
- Y 軸向下為正

### 3.3 層次結構
```
報表文檔 (Document)
  └── 頁面 (Page)
        └── PLANK (容器)
              └── 元素 (相對座標)
```

元素的絕對位置 = PLANK 位置 + 元素相對位置

## 4. 渲染管線

### 4.1 文檔加載

```
1. CRptDoc::Read(filepath)
   ├── 讀取文件內容
   ├── 驗證 Magic Header
   ├── 解析 Binary Header
   ├── 解析 DSL 文本
   └── 構建元素樹
```

### 4.2 頁面渲染 (ShowPage)

```cpp
void CRptDoc::ShowPage(HDC hdc, int page, int x, int y,
                       int width, int height, int scale, int flags)
{
    // 1. 設置設備上下文
    SaveDC(hdc);
    SetMapMode(hdc, MM_ANISOTROPIC);
    SetWindowOrgEx(hdc, 0, 0);
    SetViewportOrgEx(hdc, x, y);

    // 2. 渲染 HEAD
    if (has_border) DrawBorder();
    if (has_shadow) DrawShadow();

    // 3. 遍歷 PLANK 容器
    for each PLANK in page {
        // 計算絕對位置
        int abs_x = plank.x + offset_x;
        int abs_y = plank.y + offset_y;

        // 4. 渲染 PLANK 內的元素
        for each element in PLANK {
            switch (element.type) {
                case LABEL:
                    RenderLabel(hdc, element, abs_x, abs_y);
                    break;
                case EDIT:
                    RenderEdit(hdc, element, abs_x, abs_y);
                    break;
                case LINE:
                    RenderLine(hdc, element, abs_x, abs_y);
                    break;
                case IMAGE:
                    RenderImage(hdc, element, abs_x, abs_y);
                    break;
            }
        }
    }

    // 5. 恢復設備上下文
    RestoreDC(hdc);
}
```

### 4.3 元素渲染細節

#### 4.3.1 文本渲染 (LABEL/EDIT)

```cpp
void RenderLabel(HDC hdc, Element& elem, int base_x, int base_y)
{
    // 創建字體
    LOGFONT lf = {0};
    lf.lfHeight = -MulDiv(current_font_size, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    if (font_style & PS_FONT_BOLD)
        lf.lfWeight = FW_BOLD;
    if (font_style & PS_FONT_UNDERLINE)
        lf.lfUnderline = TRUE;

    HFONT hFont = CreateFontIndirectA(&lf);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

    // 設置對齊
    UINT align = 0;
    if (elem.style & PS_LEFT)   align = TA_LEFT;
    if (elem.style & PS_RIGHT)  align = TA_RIGHT;
    if (elem.style & PS_CENTER) align = TA_CENTER;
    SetTextAlign(hdc, align);

    // 設置顏色
    SetTextColor(hdc, text_color);
    SetBkMode(hdc, TRANSPARENT);

    // 計算位置
    int x = base_x + elem.x;
    int y = base_y + elem.y;

    // 繪製文本
    TextOutA(hdc, x, y, elem.text, strlen(elem.text));

    // 清理
    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
}
```

#### 4.3.2 線條渲染

```cpp
void RenderLine(HDC hdc, LineElement& elem, int base_x, int base_y)
{
    HPEN hPen = CreatePen(PS_SOLID, elem.thickness, RGB(0,0,0));
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);

    MoveToEx(hdc, base_x + elem.x1, base_y + elem.y1, NULL);
    LineTo(hdc, base_x + elem.x2, base_y + elem.y2);

    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
}
```

#### 4.3.3 圖片渲染

```cpp
void RenderImage(HDC hdc, ImageElement& elem, int base_x, int base_y)
{
    // 加載圖片 (BMP/JPEG)
    HBITMAP hBitmap = LoadImage(...);

    HDC hdcMem = CreateCompatibleDC(hdc);
    SelectObject(hdcMem, hBitmap);

    // 獲取圖片尺寸
    BITMAP bm;
    GetObject(hBitmap, sizeof(bm), &bm);

    // 繪製到目標位置
    BitBlt(hdc, base_x + elem.x, base_y + elem.y,
           elem.width, elem.height,
           hdcMem, 0, 0, SRCCOPY);

    DeleteDC(hdcMem);
    DeleteObject(hBitmap);
}
```

### 4.4 打印流程

```cpp
void PrintDocument(CRptDoc* doc, HDC hdcPrinter)
{
    DOCINFO di = {sizeof(DOCINFO)};
    di.lpszDocName = doc->GetTitle();

    StartDocA(hdcPrinter, &di);

    int pageCount = doc->GetPageNum();
    for (int page = 1; page <= pageCount; page++) {
        StartPage(hdcPrinter);

        // 計算縮放以適應打印紙張
        int printWidth = GetDeviceCaps(hdcPrinter, HORZRES);
        int printHeight = GetDeviceCaps(hdcPrinter, VERTRES);

        doc->ShowPage(hdcPrinter, page, 0, 0, printWidth, printHeight, 100, 0);

        EndPage(hdcPrinter);
    }

    EndDoc(hdcPrinter);
}
```

## 5. 數據綁定

### 5.1 EDIT 字段映射

EDIT 元素通過 ID 與數據源綁定：

| ID 範圍 | 用途 |
|---------|------|
| 0-99 | 標準字段 (日期、訂單號等) |
| 100+ | 表格數據行 |

### 5.2 數據填充流程

```cpp
void FillData(CRptDoc* doc, DataRecord* data)
{
    for each EDIT in doc {
        int fieldId = edit.id_num;
        const char* value = data->GetField(fieldId);
        edit.SetText(value);
    }
}
```

## 6. 輸出格式

### 6.1 PDF 生成 (MakePdf)

```cpp
int CRptDoc::MakePdf(const char* path, int dpi,
                     int startPage, int endPage,
                     int leftMargin, int rightMargin,
                     int topMargin, int bottomMargin,
                     double scaleX, double scaleY, double paperScale)
```

PDF 生成可能使用第三方庫，將 GDI 調用轉換為 PDF 繪圖指令。

### 6.2 RTF 生成 (MakeRtf)

將報表轉換為 RTF 格式，保留基本格式。

### 6.3 Excel 生成 (MakeXls)

將數據導出為 Excel 格式，主要用於表格數據。

## 7. 使用統計

基於 sample_report.tmp 分析：

| 元素類型 | 數量 |
|----------|------|
| PLANK | 93 |
| LABEL | 108 |
| EDIT | 140 |
| LINE | 9 |
| IMAGE | 6 |
| FONT | 4 |

## 8. 實現複製指南

如果要實現相容的渲染引擎：

### 8.1 解析器實現

```python
class ReportParser:
    def parse(self, filepath):
        # 1. 讀取文件
        data = open(filepath, 'rb').read()

        # 2. 驗證 Header
        if data[:14] != b'Datawin Report':
            raise ValueError("Invalid file format")

        # 3. 提取元數據
        self.title = data[0x48:data.find(b'\x00', 0x48)].decode()

        # 4. 解析 DSL
        text = data[0x2BA:].decode('ascii', errors='ignore')
        self.elements = self.parse_dsl(text)
```

### 8.2 渲染器實現

```python
class ReportRenderer:
    def render(self, doc, canvas):
        for plank in doc.planks:
            self.render_plank(plank, canvas)

    def render_plank(self, plank, canvas):
        canvas.save()
        canvas.translate(plank.x, plank.y)

        for elem in plank.children:
            if elem.type == 'LABEL':
                self.render_text(elem, canvas)
            elif elem.type == 'EDIT':
                self.render_text(elem, canvas)
            elif elem.type == 'LINE':
                self.render_line(elem, canvas)
            elif elem.type == 'IMAGE':
                self.render_image(elem, canvas)

        canvas.restore()
```

## 9. 總結

nrp32.exe 使用一種自定義的報表 DSL 格式，通過以下方式實現文檔排版和渲染：

1. **文件格式**: 二進制頭 + 文本 DSL
2. **元素模型**: 層次化容器 (PLANK) + 內容元素 (LABEL, EDIT, LINE, IMAGE)
3. **座標系統**: 相對座標，單位可能是 0.1mm
4. **渲染引擎**: Windows GDI，使用標準 GDI 函數
5. **輸出能力**: 屏幕預覽、打印、PDF/RTF/XLS 導出

這個設計允許靈活的報表佈局定義，同時保持較低的複雜度和良好的 Windows 平台兼容性。

---

*文檔生成日期: 2025-12-23*
*逆向工程工具: pefile, capstone, custom parsers*
