# TEM - 報價單模組

```yaml
---
module_id: tem
name_zh: "報價單"
name_en: "Quotation"
table_range: tem01-tem17
field_prefix: "e{table_char}{seq}"
layer: transaction
tables: 17
primary_key: "[[tem01.ea01]]"
flow_position: 1
receives_from: ["[[tbm01]]", "[[tdm01]]"]
sends_to: ["[[tfm01]]"]
index: "./_index.yaml"
practical_usage: "tem01/tem02 未使用; tem05 (訂單 BOM) 有使用"
---
```

## 模組概述

TEM 包含報價單功能及訂單專屬 BOM 儲存。

**實務說明**:
- `tem01`/`tem02` (報價單) - **未使用**，實際業務直接從 tfm 開始
- `tem05` (訂單 BOM) - **有使用**，儲存訂單專屬 BOM

**關鍵角色**: `[[tem05]]` 儲存訂單專屬 BOM (建立訂單時從 `[[tdm05]]` 複製)。

**實際流程 (跳過報價單):**
```
[[tbm01]] + [[tdm01]] --> [[tfm01]] (訂單) --> [[tgm01]] (採購)
                               |
                               +--> [[tem05]] (訂單 BOM，自動從 [[tdm05]] 複製)
```

---

## 資料表清單

| 資料表 | 用途 | 主鍵 |
|-------|------|------|
| tem01 | **報價單主檔** (53 欄位) | `ea01` |
| tem02 | **報價單明細** (47 欄位) | `(eb01, eb02)` |
| tem03 | 報價單子描述 | `(ec01, ec02, ec03)` |
| tem04 | 報價單備註 | - |
| tem05 | **訂單 BOM** (20 欄位) | `(ee011, ee02, ee03)` |
| tem06-10 | 保留 | - |
| tem11-17 | 擴充資料 | - |

---

## TEM01 - 報價單主檔

### 欄位定義

```yaml
table: tem01
name: "報價單主檔"
total_fields: 53
primary_key: ea01
```

| 欄位 | 類型 | 說明 | 參照 |
|------|------|------|------|
| `ea01` | varchar(10) | **報價單號** (主鍵) | |
| `ea02` | varchar(10) | **客戶代碼** | `[[tbm01.ba01]]` |
| `ea03` | varchar(8) | 報價日期 | YYYYMMDD |
| `ea04` | varchar(3) | 業務代表 | |
| `ea05` | varchar(5) | 幣別 | `[[tam08.ha01]]` |
| `ea06` | varchar(50) | 客戶名稱 | |
| `ea07` | int | 項目數 | |
| `ea08` | float | 總金額 | |
| `ea09` | char(1) | 狀態 (N=新建, C=已轉換) | |
| `ea10` | varchar(10) | 轉換至 PI | `[[tfm01.fa01]]` |

---

## TEM02 - 報價單明細

### 欄位定義

```yaml
table: tem02
name: "報價單明細"
total_fields: 47
primary_key: "(eb01, eb02)"
```

| 欄位 | 類型 | 說明 | 參照 |
|------|------|------|------|
| `eb01` | varchar(10) | **報價單號** | `[[tem01.ea01]]` |
| `eb02` | float | **明細序號** | 主鍵部分 |
| `eb03` | varchar(20) | **產品代碼** | `[[tdm01.da01]]` |
| `eb04` | varchar(50) | 產品名稱 | |
| `eb05` | float | 數量 | |
| `eb06` | varchar(6) | 單位 | |
| `eb07` | float | 單價 | |
| `eb08` | float | 行金額 | |
| `eb09` | float | 折扣 % | |
| `eb10` | float | 淨額 | |

---

## TEM05 - 訂單 BOM (關鍵)

### 欄位定義

```yaml
table: tem05
name: "訂單專屬物料清單"
total_fields: 20
primary_key: "(ee011, ee02, ee03)"
purpose: "儲存每張訂單專屬的 BOM (從 [[tdm05]] 複製)"
critical: true
```

| 欄位 | 類型 | 說明 | 參照 |
|------|------|------|------|
| `ee011` | varchar(10) | **訂單號** | `[[tfm01.fa01]]` |
| `ee02` | varchar(20) | **產品代碼** | `[[tdm01.da01]]` |
| `ee03` | varchar(20) | **零件代碼** | `[[tdm01.da01]]` |
| `ee04` | float | **比例分子** | 計算用 |
| `ee05` | float | **比例分母** | 計算用 |
| `ee06` | varchar(10) | **供應商代碼** | `[[tcm01.ca01]]` |
| `ee07` | int | BOM 序號 | |
| `ee08` | float | 零件價格 | |
| `ee09` | varchar(6) | 單位 | |
| `ee10` | char(1) | 主件 (Y/N) | |

### 主鍵說明

```yaml
pk_structure:
  ee011: "訂單號 (連結至 [[tfm01.fa01]])"
  ee02: "訂購的產品代碼"
  ee03: "BOM 中的零件代碼"
  uniqueness: "每張訂單的每個產品的每個零件一筆記錄"
```

### BOM 複製流程

```yaml
trigger: "當 [[tfm02]] 明細建立時"
source: "[[tdm05]] (標準 BOM)"
target: "[[tem05]] (訂單 BOM)"

process:
  1. "對每一筆新增的 [[tfm02]] 明細:"
  2. "  查詢 [[tdm05]] WHERE de01 = [[tfm02.fb03]]"
  3. "  將每一筆 BOM 記錄複製到 [[tem05]]:"
  4. "    ee011 = [[tfm01.fa01]] (訂單號)"
  5. "    ee02 = [[tfm02.fb03]] (產品)"
  6. "    ee03-ee10 從 de03-de10 複製"
```

---

## 採購計算公式

```yaml
formula: "採購數量 = 訂單數量 * (ee04 / ee05)"

example:
  order_no: "00048"
  product: "WIDGET-A"
  order_qty: 1000  # [[tfm02.fb09]]
  component: "SCREW-01"
  ee04: 4   # 需要 4 顆螺絲
  ee05: 1   # 每 1 個產品
  supplier: "SUP-001"  # ee06
  result: 4000  # 此供應商的採購數量
```

### SQL 實作

```sql
-- 從訂單產生採購需求
SELECT
    e.ee06 AS [供應商],
    e.ee03 AS [零件],
    e.ee10 AS [主件],
    SUM(CAST((f.fb09 * e.ee04 / e.ee05) AS DECIMAL(10,2))) AS [採購數量],
    e.ee08 AS [單價],
    SUM(CAST((f.fb09 * e.ee04 / e.ee05) AS DECIMAL(10,2))) * e.ee08 AS [總金額]
FROM [[tfm02]] f
INNER JOIN [[tem05]] e ON e.ee011 = f.fb01 AND e.ee02 = f.fb03
WHERE f.fb01 = @OrderNo
GROUP BY e.ee06, e.ee03, e.ee10, e.ee08
ORDER BY e.ee06, e.ee10 DESC, e.ee03
```

---

## 跨模組整合

### 上游 (接收資料)

```yaml
from_tbm:
  source: "[[tbm01]]"
  provides: "報價單的客戶資訊"
  field_map:
    - "[[tbm01.ba01]] -> [[tem01.ea02]]"

from_tdm:
  source: "[[tdm01]], [[tdm05]]"
  provides: "產品資訊、標準 BOM"
  trigger: "建立訂單時複製 BOM"
```

### 下游 (傳送資料)

```yaml
to_tfm:
  trigger: "報價單轉換"
  data_flow:
    - "[[tem01]] -> [[tfm01]] (表頭)"
    - "[[tem02]] -> [[tfm02]] (明細)"
  triggers: ["將 [[tdm05]] 複製到 [[tem05]]"]

to_tgm:
  via: "[[tem05]] (訂單 BOM)"
  provides: "產生採購單所需的零件需求"
  link: "[[tem05.ee011]] = [[tfm01.fa01]] = [[tgm01.ga2301]]"
```

---

## 完整訂單到採購追蹤

```
[[tem01]] (報價單)
    |
    v (轉換為訂單)
[[tfm01]] (訂單)
    |
    +---> [[tfm02]] (訂單明細)
    |         |
    |         v (觸發 BOM 複製)
    |     [[tem05]] (訂單 BOM)
    |         |
    |         +--- ee011 = fa01 (訂單號)
    |         +--- ee06 = 供應商
    |         +--- ee04/ee05 = 比例
    |
    v (依 ee06 分群產生採購單)
[[tgm01]] (採購單)
    |
    +--- ga2301 = fa01 (連結回訂單)
    |
    v
[[tgm02]] (採購明細)
    |
    +--- gb2601 = fa01 (連結回訂單)
    +--- gb09 = 計算數量
```

---

## 常用查詢

### 取得報價單及項目

```sql
SELECT
    q.ea01 AS [報價單],
    q.ea02 AS [客戶],
    q.ea03 AS [日期],
    qd.eb03 AS [產品],
    qd.eb05 AS [數量],
    qd.eb07 AS [價格],
    qd.eb10 AS [金額]
FROM [[tem01]] q
INNER JOIN [[tem02]] qd ON qd.eb01 = q.ea01
WHERE q.ea01 = @QuotationNo
ORDER BY qd.eb02
```

### 取得訂單 BOM

```sql
SELECT
    b.ee011 AS [訂單],
    b.ee02 AS [產品],
    b.ee03 AS [零件],
    b.ee06 AS [供應商],
    b.ee04 AS [比例分子],
    b.ee05 AS [比例分母],
    b.ee10 AS [主件]
FROM [[tem05]] b
WHERE b.ee011 = @OrderNo
ORDER BY b.ee02, b.ee07
```

### 追蹤 BOM 到採購

```sql
-- 從訂單 BOM 到採購單的完整追蹤
SELECT
    b.ee011 AS [訂單],
    b.ee02 AS [產品],
    b.ee03 AS [零件],
    b.ee06 AS [供應商],
    od.fb09 AS [訂單數量],
    CAST((od.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [需求數量],
    p.ga01 AS [採購單號],
    pd.gb09 AS [採購數量]
FROM [[tem05]] b
INNER JOIN [[tfm02]] od ON od.fb01 = b.ee011 AND od.fb03 = b.ee02
LEFT JOIN [[tgm01]] p ON p.ga2301 = b.ee011 AND p.ga04 = b.ee06
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01 AND pd.gb04 = b.ee03
WHERE b.ee011 = @OrderNo
ORDER BY b.ee06, b.ee03
```

---

## 導覽

- **上一篇**: `./05-tdm.md` (產品主檔)
- **下一篇**: `./07-tfm.md` (銷售訂單)
- **索引**: `./_index.yaml`
- **概述**: `./00-overview.md`
