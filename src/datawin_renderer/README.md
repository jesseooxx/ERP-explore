# Datawin Report Renderer

Python 實現的 Datawin 報表渲染器，完全相容 nrp32.exe 的報表格式。

## 功能特性

- ✅ 完整支持 Datawin Report `.tmp` 文件格式
- ✅ 解析 DSL 語法（PLANK, LABEL, EDIT, LINE, IMAGE, FONT）
- ✅ 支持數據綁定（從 JSON, CSV, 字典填充 EDIT 字段）
- ✅ PDF 輸出（使用 ReportLab）
- ✅ 支持文本對齊（左、右、居中）
- ✅ 支持字體樣式（粗體、下劃線）
- ✅ 支持圖片渲染
- ✅ 支持線條和邊框

## 安裝

```bash
pip install reportlab Pillow
```

## 快速開始

### 1. 基本渲染（無數據綁定）

```python
from src.datawin_renderer import ReportParser, PDFRenderer

# 解析模板
parser = ReportParser("invoice.tmp")
document = parser.parse()

# 渲染為 PDF
renderer = PDFRenderer()
renderer.render(document, "output.pdf")
```

### 2. 數據綁定渲染

```python
from src.datawin_renderer import ReportParser, PDFRenderer, DataBinderBuilder

# 解析模板
parser = ReportParser("invoice.tmp")
document = parser.parse()

# 創建數據綁定
binder = (DataBinderBuilder()
          .add_field(1, "2024-12-23")           # 日期
          .add_field(2, "ORD-2024-001")         # 訂單號
          .add_field(3, "REF-ABC-123")          # 參考號
          .add_field(4, "CUST-12345")           # 客戶編號
          .add_field(5, "+886-2-1234-5678")     # 電話
          .add_field(6, "+886-2-1234-5679")     # 傳真
          .build())

# 綁定數據到文檔
binder.bind(document)

# 渲染
renderer = PDFRenderer()
renderer.render(document, "invoice_filled.pdf")
```

### 3. 從 JSON 文件加載數據

**data.json:**
```json
{
  "1": "2024-12-23",
  "2": "ORD-2024-001",
  "3": "REF-ABC-123",
  "4": "CUST-12345",
  "5": "+886-2-1234-5678",
  "6": "+886-2-1234-5679"
}
```

**Python 代碼:**
```python
from src.datawin_renderer import ReportParser, PDFRenderer, DataBinder

parser = ReportParser("invoice.tmp")
document = parser.parse()

# 從 JSON 加載數據
binder = DataBinder.from_json("data.json")
binder.bind(document)

renderer = PDFRenderer()
renderer.render(document, "invoice.pdf")
```

### 4. 一行渲染

```python
from src.datawin_renderer.renderer import render_report

render_report(
    "invoice.tmp",
    "output.pdf",
    data_dict={
        1: "2024-12-23",
        2: "ORD-2024-001",
        4: "CUST-12345"
    }
)
```

## API 參考

### ReportParser

```python
parser = ReportParser(filepath)
document = parser.parse()
```

**屬性:**
- `document.title` - 報表標題
- `document.elements` - 所有元素列表
- `document.get_planks()` - 獲取所有 PLANK 容器
- `document.get_head()` - 獲取 HEAD 元素

### DataBinder

```python
# 從字典創建
binder = DataBinder.from_dict({1: "value1", 2: "value2"})

# 從 JSON 創建
binder = DataBinder.from_json("data.json")

# 從 CSV 創建
binder = DataBinder.from_csv("data.csv")

# 綁定數據
binder.bind(document)

# 驗證數據完整性
validation = binder.validate(document)
print(validation['valid'])  # True/False
print(validation['missing_fields'])  # [缺失的字段 ID]
```

### DataBinderBuilder

流式 API 用於構建數據綁定：

```python
binder = (DataBinderBuilder()
          .add_field(1, "value1")
          .add_field(2, "value2")
          .add_fields_from_dict({3: "value3", 4: "value4"})
          .add_fields_from_json("extra_data.json")
          .build())
```

### PDFRenderer

```python
from reportlab.lib.pagesizes import A4, letter

renderer = PDFRenderer(
    page_size=A4,      # 頁面大小
    margin=10*mm       # 頁邊距
)
renderer.render(document, "output.pdf")
```

### 便捷函數

```python
from src.datawin_renderer.renderer import render_report, RenderOptions

options = RenderOptions(
    page_size=letter,
    margin=15*mm,
    scale=1.0
)

render_report(
    template_path="invoice.tmp",
    output_path="output.pdf",
    data_dict={1: "data"},
    options=options
)
```

## 數據字段映射

EDIT 字段 ID 與數據的對應關係（基於 PROFORMA INVOICE 範例）：

| Field ID | 說明 |
|----------|------|
| 0 | 報表標題 |
| 1 | 日期 |
| 2 | 訂單號 |
| 3 | 參考號 |
| 4 | 客戶編號 |
| 5 | 電話 |
| 6 | 傳真 |
| 7 | 預計交貨日 (ETD) |
| 8+ | 其他自定義字段 |

## 座標系統

- 單位：0.1mm (根據逆向工程分析)
- 原點：左上角
- X 軸：向右為正
- Y 軸：向下為正

## 支持的元素類型

| 元素 | 說明 |
|------|------|
| HEAD | 頁面頭部 |
| PLANK | 容器/分組元素 |
| LABEL | 靜態文本 |
| EDIT | 數據字段（可綁定） |
| LINE | 線條 |
| IMAGE | 圖片 |
| FONT | 字體定義 |

## 支持的樣式標誌

| 標誌 | 說明 |
|------|------|
| PS_LEFT | 左對齊 |
| PS_RIGHT | 右對齊 |
| PS_CENTER | 居中對齊 |
| PS_BORDER | 繪製邊框 |
| PS_SHADOW | 添加陰影 |
| PS_FONT_BOLD | 粗體字 |
| PS_FONT_UNDERLINE | 下劃線 |

## 範例

完整範例請參見 `examples/render_example.py`

```bash
cd "C:\真桌面\Claude code\ERP explore"
python examples/render_example.py
```

這將生成 4 個示範 PDF：
- `output/example1_simple.pdf` - 簡單渲染
- `output/example2_with_data.pdf` - 數據綁定渲染
- `output/example3_from_json.pdf` - 從 JSON 加載數據
- `output/example4_oneline.pdf` - 一行代碼渲染

## 技術架構

```
Datawin Renderer
├── parser.py          # DSL 解析器
├── data_binder.py     # 數據綁定模組
├── renderer.py        # PDF 渲染引擎
└── __init__.py        # 模組導出
```

### 渲染流程

```
.tmp 文件
    ↓
ReportParser.parse()
    ↓
ReportDocument (內存模型)
    ↓
DataBinder.bind() (可選)
    ↓
PDFRenderer.render()
    ↓
PDF 文件
```

## 相容性

本渲染器完全相容 nrp32.exe 的報表格式：
- ✅ 相同的 DSL 語法
- ✅ 相同的二進制文件頭格式
- ✅ 相同的座標系統
- ✅ 相同的樣式標誌
- ✅ 相同的元素渲染邏輯

## 限制

- 目前只支持單頁報表
- 圖片路徑必須是絕對路徑或相對於當前工作目錄
- 字體僅支持 Helvetica/Times（PDF 標準字體）

## 授權

基於 nrp32.exe 逆向工程實現，用於教育和研究目的。

## 相關文檔

- [NRP32 渲染模型完整文檔](../../reverse_engineering/NRP32_RENDERING_MODEL.md)
- [逆向工程報告](../../reverse_engineering/)
