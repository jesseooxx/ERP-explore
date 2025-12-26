# TDM - 產品主檔

```yaml
---
module_id: tdm
name_zh: "產品主檔"
name_en: "Product Master"
table_range: tdm01-tdm26
field_prefix: "d{table_char}{seq}"
layer: master_data
tables: 26
primary_key: "[[tdm01.da01]]"
index: "./_index.yaml"
---
```

## 模組概述

TDM 是核心產品主檔模組，包含產品資訊、標準 BOM、定價及包裝資料。主鍵 `[[tdm01.da01]]` 在所有交易模組中被參照。

**關鍵特性**: `[[tdm05]]` 中的標準 BOM 會在建立訂單時複製到訂單 BOM `[[tem05]]`。

---

## 資料表清單

| 資料表 | 用途 | 主鍵 |
|-------|------|------|
| tdm01 | **產品主檔** (85 欄位) | `da01` |
| tdm02 | 產品子描述 | `(db01, db02)` |
| tdm03 | 產品圖片 | `(dc01, dc02)` |
| tdm04 | 產品類別 | `dd01` |
| tdm05 | **標準 BOM** (19 欄位) | `(de01, de02)` |
| tdm06 | BOM 替代方案 | - |
| tdm07 | 產品規格 | - |
| tdm08 | **包裝資料** | `(dh01, dh02)` |
| tdm09 | **價格等級** | `(di01, di02)` |
| tdm10-15 | 產品屬性 | - |
| tdm16-20 | 保留 | - |
| tdm21-26 | 擴充資料 | - |

---

## TDM01 - 產品主檔

### 欄位定義

```yaml
table: tdm01
name: "產品主檔"
total_fields: 85
primary_key: da01
```

| 欄位 | 類型 | 說明 | 被參照於 |
|------|------|------|----------|
| `da01` | varchar(20) | **產品代碼** (主鍵) | `[[tdm05.de01]]`, `[[tem02.eb03]]`, `[[tfm02.fb03]]`, `[[tgm02.gb03]]`, `[[thm02.hb02]]` |
| `da02` | varchar(50) | 產品名稱 1 | |
| `da03` | varchar(50) | 產品名稱 2 | |
| `da04` | varchar(10) | 類別代碼 | `[[tdm04.dd01]]` |
| `da05` | varchar(6) | 計量單位 | |
| `da06` | float | 淨重 | |
| `da07` | float | 毛重 | |
| `da08` | float | 體積 (CBM) | |
| `da09` | float | 標準成本 | |
| `da10` | float | 標準價格 | |
| `da11` | varchar(10) | 預設供應商 | `[[tcm01.ca01]]` |
| `da12` | char(1) | 啟用 (Y/N) | |

---

## TDM05 - 標準 BOM (關鍵)

### 欄位定義

```yaml
table: tdm05
name: "標準物料清單"
total_fields: 19
primary_key: "(de01, de02)"
purpose: "定義每個產品的零件及供應商"
```

| 欄位 | 類型 | 說明 | 參照 |
|------|------|------|------|
| `de01` | varchar(20) | **產品代碼** | `[[tdm01.da01]]` |
| `de02` | int | **序號** | 主鍵部分 |
| `de03` | varchar(20) | 零件代碼 | `[[tdm01.da01]]` |
| `de04` | float | **比例分子** | BOM 計算 |
| `de05` | varchar(10) | **供應商代碼** | `[[tcm01.ca01]]` |
| `de06` | float | **比例分母** | BOM 計算 |
| `de07` | float | 零件價格 | |
| `de08` | varchar(6) | 單位 | |
| `de09` | char(1) | 主件標記 (Y/N) | |
| `de10` | varchar(50) | 零件說明 | |

### BOM 計算

```yaml
formula: "零件數量 = 訂單數量 * (de04 / de06)"
example:
  product: "WIDGET-A"
  order_qty: 1000
  component: "SCREW-01"
  de04: 4   # 需要 4 顆螺絲
  de06: 1   # 每 1 個產品
  result: 4000  # 採購數量
```

### 複製觸發

```yaml
trigger: "當 [[tfm02]] 新增時 (訂單明細建立)"
action: "將 [[tdm05]] 複製到 [[tem05]] 作為訂單專屬 BOM"
mapping:
  - "[[tdm05.de01]] -> [[tem05.ee02]] (產品)"
  - "[[tdm05.de02]] -> [[tem05.ee07]] (序號)"
  - "[[tdm05.de03]] -> [[tem05.ee03]] (零件)"
  - "[[tdm05.de04]] -> [[tem05.ee04]] (比例分子)"
  - "[[tdm05.de05]] -> [[tem05.ee06]] (供應商)"
  - "[[tdm05.de06]] -> [[tem05.ee05]] (比例分母)"
  - "[[tfm01.fa01]] -> [[tem05.ee011]] (訂單號)"
```

---

## TDM08 - 包裝資料

### 欄位定義

```yaml
table: tdm08
name: "產品包裝規格"
primary_key: "(dh01, dh02)"
purpose: "[[thm03]] 的預設包裝尺寸"
```

| 欄位 | 類型 | 說明 |
|------|------|------|
| `dh01` | varchar(20) | **產品代碼** -> `[[tdm01.da01]]` |
| `dh02` | int | 包裝類型序號 |
| `dh03` | int | 內盒數量 |
| `dh04` | int | 內盒裝外箱數量 |
| `dh05` | float | 外箱長度 (cm) |
| `dh06` | float | 外箱寬度 (cm) |
| `dh07` | float | 外箱高度 (cm) |
| `dh08` | float | 淨重 (kg) |
| `dh09` | float | 毛重 (kg) |

---

## TDM09 - 價格等級

### 欄位定義

```yaml
table: tdm09
name: "產品價格等級"
primary_key: "(di01, di02)"
```

| 欄位 | 類型 | 說明 |
|------|------|------|
| `di01` | varchar(20) | **產品代碼** -> `[[tdm01.da01]]` |
| `di02` | int | 價格等級 (1-9) |
| `di03` | float | 單價 |
| `di04` | varchar(5) | 幣別 |
| `di05` | int | 此等級最小數量 |

---

## 跨模組參照

### 產品參照鏈

```yaml
master: "[[tdm01.da01]]"
referenced_by:
  tdm05: "[[tdm05.de01]] - 標準 BOM"
  tem: "[[tem02.eb03]] - 報價單項目"
  tfm: "[[tfm02.fb03]] - 訂單項目"
  tgm: "[[tgm02.gb03]] - 採購項目"
  thm: "[[thm02.hb02]] - 發票項目"
```

### BOM 流程

```
[[tdm05]] (標準 BOM)
    |
    | [訂單建立觸發]
    v
[[tem05]] (訂單專屬 BOM)
    |
    | ee011 = [[tfm01.fa01]] (訂單號)
    | ee06 = 供應商
    |
    v
[[tgm01]]/[[tgm02]] (採購單)
    |
    | 依 ee06 (供應商) 分群
    | 數量 = [[tfm02.fb09]] * (ee04 / ee05)
```

---

## 常用查詢

### 取得產品及其 BOM

```sql
SELECT
    p.da01 AS [產品],
    p.da02 AS [名稱],
    b.de02 AS [序號],
    b.de03 AS [零件],
    b.de04 AS [比例分子],
    b.de06 AS [比例分母],
    s.ca02 AS [供應商]
FROM [[tdm01]] p
INNER JOIN [[tdm05]] b ON b.de01 = p.da01
LEFT JOIN [[tcm01]] s ON s.ca01 = b.de05
WHERE p.da01 = @ProductCode
ORDER BY b.de02
```

### 計算採購需求

```sql
-- 針對指定訂單，計算零件需求
SELECT
    b.de03 AS [零件],
    b.de05 AS [供應商],
    SUM(CAST((od.fb09 * b.de04 / b.de06) AS DECIMAL(10,2))) AS [需求數量]
FROM [[tfm02]] od
INNER JOIN [[tem05]] b ON b.ee011 = od.fb01 AND b.ee02 = od.fb03
WHERE od.fb01 = @OrderNo
GROUP BY b.de03, b.de05
ORDER BY b.de05, b.de03
```

### 取得包裝預設值

```sql
SELECT
    p.da01 AS [產品],
    pk.dh03 AS [內盒數量],
    pk.dh04 AS [外箱數量],
    pk.dh05 AS [長度],
    pk.dh06 AS [寬度],
    pk.dh07 AS [高度],
    (pk.dh05 * pk.dh06 * pk.dh07 / 1000000) AS [CBM]
FROM [[tdm01]] p
INNER JOIN [[tdm08]] pk ON pk.dh01 = p.da01
WHERE p.da01 = @ProductCode
```

---

## 導覽

- **上一篇**: `./04-tcm.md` (供應商主檔)
- **下一篇**: `./06-tem.md` (報價單)
- **索引**: `./_index.yaml`
- **相關**: `./08-tgm.md` (使用 BOM 進行採購計算)
