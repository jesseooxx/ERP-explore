# 座標系統問題分析

## 關鍵發現

### 1. Y 座標範圍異常小

```
模板宣稱: page_height = 1200
實際 Y 範圍: 0 ~ 200  ← 只有宣稱的 17%！
```

### 2. PLANK 分佈模式

```
所有 93 個 PLANK 的 Y 座標只有 6 個不同值:
[0, 70, 105, 165, 185, 200]

大部分 PLANK: Y = 0
```

### 3. 特殊 PLANK (ID 999-1004)

```
全部 6 個圖片 PLANK:
- Y 座標 = 0
- Height = 120 或 0
- 全部位於文檔開頭
```

## 問題根源

### 錯誤的理解

❌ **我們的假設**: Y 座標是文檔內的絕對位置
   - Y=0 在頂部
   - Y=200 在底部
   - 所有內容在一個連續的座標空間

### 正確的理解

✅ **實際情況**: Y 座標是**頁面內的相對位置**
   - 每個"邏輯頁面"有自己的座標系統
   - Y=0 是當前頁面的頂部
   - 不同頁面的元素可以有相同的 Y 座標

## 原始 nrp32.exe 的分頁邏輯

根據分析，nrp32.exe 的分頁規則：

### 規則 1: 特殊 PLANK ID 觸發新頁面

```
ID >= 999 的 PLANK → 單獨頁面
示例: ID 999, 1000, 1001, 1002, 1003, 1004 (共 6 個)
```

但原始 PDF 只有 4 頁，所以不是簡單的 1 PLANK = 1 頁

### 規則 2: 圖片 PLANK 分組

```
頁 1: 主報表內容 (PLANK ID 0-300)
頁 2-4: 圖片頁面 (PLANK ID 999-1004，可能2個一頁)
```

### 規則 3: 內容類型分離

從原始 PDF 提取的內容：
```
頁 1: 發票頭 + 客戶信息
頁 2: 商品明細表 (開始)
頁 3: 商品明細表 (繼續)
頁 4: 簽名確認
```

這表示不是按 PLANK 分頁，而是按**內容邏輯**分頁。

## 座標轉換問題

### 當前的轉換

```python
DW_TO_POINTS = 0.1 * (72 / 25.4)  # ≈ 0.283

# 假設 1 單位 = 0.1mm
```

### 實際測試

```
模板 X 範圍: 0 ~ 597
PDF 頁面寬度: 595 points

597 * 0.283 = 168.8 points  ← 錯誤！應該接近 595

正確比例應該是:
597 / 595 ≈ 1.003
即: 1 模板單位 ≈ 1 PDF point
```

### 修正後的轉換

```python
# 方案 A: 直接對應
DW_TO_POINTS = 1.0  # 1 模板單位 = 1 PDF point

# 方案 B: 按頁面寬度縮放
scale_x = 595 / 900  # 900 是模板宣稱的 page_width
scale_y = 842 / 1200  # 1200 是模板宣稱的 page_height
```

## Y 軸方向問題

### PDF 座標系統

```
(0,0) 在左下角
Y 軸向上增加

(0, 842) ← 頁面頂部
    ↑
    |
    |
(0, 0) ← 頁面底部（原點）
```

### 模板座標系統

```
(0,0) 在左上角
Y 軸向下增加

(0, 0) ← 頁面頂部（原點）
    ↓
    |
    |
(0, 1200) ← 頁面底部
```

### 當前的 Y 轉換

```python
y = page_height - margin - base_y - (elem.y * DW_TO_POINTS) - (elem.height * DW_TO_POINTS)
```

這個公式**理論上正確**，但：
1. 如果 `DW_TO_POINTS` 錯誤，整個計算都錯
2. 沒有考慮多頁情況

## 建議的修正方案

### 修正 1: 座標轉換比例

```python
class FixedPDFRenderer:
    # 根據實際測試，模板單位接近 PDF points
    # 但需要按頁面尺寸縮放

    def __init__(self, page_size=A4):
        self.page_width, self.page_height = page_size

        # 縮放因子（模板 → PDF）
        # 模板: 900 x 1200
        # A4:   595 x 842
        self.scale_x = self.page_width / 900
        self.scale_y = self.page_height / 1200

    def convert_x(self, x):
        return x * self.scale_x

    def convert_y(self, y, page_height):
        # Y 軸反轉 + 縮放
        return page_height - (y * self.scale_y)
```

### 修正 2: 多頁渲染

```python
def detect_pages(self, document):
    """檢測分頁邏輯"""
    pages = []

    # 分離不同類型的 PLANK
    header_planks = []    # Y < 50
    content_planks = []   # 50 <= Y < 150
    footer_planks = []    # Y >= 150
    image_planks = []     # ID >= 999

    for plank in document.get_planks():
        if plank.id_num >= 999:
            image_planks.append(plank)
        elif plank.y < 50:
            header_planks.append(plank)
        elif plank.y < 150:
            content_planks.append(plank)
        else:
            footer_planks.append(plank)

    # 組合頁面
    if header_planks or content_planks:
        pages.append(header_planks + content_planks)

    # 圖片頁面
    for img_plank in image_planks:
        pages.append([img_plank])

    return pages
```

### 修正 3: 數據綁定

```python
# 原始 PDF 有實際數據，我們的只有佔位符
# 需要提取實際數據或使用測試數據

test_data = {
    1: "DEC. 23, 2025",           # Date
    2: "506046",                   # ORDER
    3: "T25C22",                   # Ref
    4: "604",                      # Cust#
    5: "604 882 2026",             # Tel
    6: "604 882 1494",             # Fax
    # ... 更多字段
}
```

## 下一步行動

1. ✅ **立即修正**: 座標轉換比例
2. ✅ **實現**: 多頁渲染邏輯
3. ✅ **測試**: 使用實際數據重新渲染
4. ✅ **驗證**: 與原始 PDF 視覺對比

---

*分析完成時間: 2025-12-23*
*結論: 座標轉換錯誤 + 缺少分頁邏輯 + 缺少數據綁定*
