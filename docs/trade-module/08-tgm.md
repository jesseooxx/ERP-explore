# TGM - 採購單模組 (PO)

```yaml
---
module_id: tgm
name_zh: "採購單"
name_en: "Purchase Order"
table_range: tgm01-tgm09
field_prefix: "g{table_char}{seq}"
primary_key: "[[tgm01.ga01]]"
flow_position: 3
receives_from: ["[[tfm01]]", "[[tfm02]]", "[[tem05]]"]
sends_to: ["[[thm01]]", "[[tlm09]]"]
index: "./_index.yaml"
---
```

## 模組概述

TGM 模組處理從銷售訂單 (PI) 產生的採購單 (PO)。每張 PO 透過 `ga2301` 和 `gb2601` 欄位連結回其來源 PI。

**流程位置:**
```
[[tfm01]] (訂單) + [[tem05]] (BOM) --> [[tgm01]] (採購單) --> [[thm01]] (出貨單)
                                                          --> [[tlm09]] (應付帳款)
```

---

## 資料表清單

| 資料表 | 記錄數 | 用途 | 主鍵 |
|-------|---------|---------|-------------|
| tgm01 | 9,139 | 採購主檔 | `ga01` |
| tgm02 | 28,204 | 採購明細 | `(gb01, gb02)` |
| tgm03 | 31,535 | 採購批次/排程 | `(gc01, gc02, gc03, gc04, ...)` |
| tgm04 | 12,415 | 採購彙總 | `(gd01, gd02, gd03)` |
| tgm05-09 | 0-4 | 輔助資料表 (大多未使用) | 各異 |

---

## TGM01 - 採購主檔

### 欄位定義

```yaml
table: tgm01
name: "採購單主檔"
records: 9139
total_fields: 99
primary_key: ga01
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `ga01` | varchar(10) | NO | **PO 編號** | 主鍵 |
| `ga02` | char(1) | YES | 類型 (F/I/S) | |
| `ga03` | varchar(8) | YES | PO 日期 (YYYYMMDD) | |
| `ga04` | varchar(10) | YES | **供應商代碼** | `[[tcm01.ca01]]` |
| `ga05` | varchar(3) | YES | 業務員 | |
| `ga06` | varchar(5) | YES | **幣別** | `[[tam08.ha01]]` |
| `ga07` | varchar(30) | YES | 供應商名稱 | |
| `ga09` | int | YES | 項目數 | |
| `ga12` | varchar(20) | YES | 裝貨港 | |
| `ga13` | varchar(10) | YES | 客戶代碼 | `[[tbm01.ba01]]` |
| `ga15` | varchar(20) | YES | 目的地 | |
| `ga17` | varchar(6) | YES | 貿易條件 | |
| `ga2301` | varchar(10) | YES | **連結至 PI** | `[[tfm01.fa01]]` |
| `ga37` | float | YES | 總金額 | |
| `ga59` | varchar(8) | NO | 最後更新日期 | |

### 關鍵連結欄位

```yaml
field: ga2301
purpose: "將 PO 連結回來源 PI"
relationship: "[[tgm01.ga2301]] -> [[tfm01.fa01]]"
usage: "追溯採購單至客戶訂單"
```

---

## TGM02 - 採購明細

### 欄位定義

```yaml
table: tgm02
name: "採購單明細"
records: 28204
total_fields: 59
primary_key: "(gb01, gb02)"
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `gb01` | varchar(10) | NO | **PO 編號** | `[[tgm01.ga01]]` |
| `gb02` | float | NO | **行序號** | 主鍵組成 |
| `gb03` | varchar(20) | YES | **產品代碼** | `[[tdm01.da01]]` |
| `gb04` | varchar(20) | YES | 元件代碼 | |
| `gb07` | varchar(30) | YES | 產品名稱 1 | |
| `gb08` | varchar(30) | YES | 產品名稱 2 | |
| `gb09` | float | YES | **採購數量** | 計算值 |
| `gb10` | varchar(6) | YES | 單位 | |
| `gb11` | float | YES | 單價 | |
| `gb12` | float | YES | 行小計 | |
| `gb131` | char(1) | YES | 主件旗標 (Y/N) | |
| `gb19` | float | YES | 擴展價格 | |
| `gb20` | float | YES | 行總計 | |
| `gb2601` | varchar(10) | YES | **連結至 PI** | `[[tfm01.fa01]]` |

### 關鍵連結欄位

```yaml
field: gb2601
purpose: "將 PO 明細行連結回來源 PI"
relationship: "[[tgm02.gb2601]] -> [[tfm01.fa01]]"
usage: "追溯每個採購項目至訂單"
```

---

## TGM03 - 採購批次/排程

### 欄位定義

```yaml
table: tgm03
name: "採購批次排程"
records: 31535
total_fields: 26
primary_key: "(gc01, gc02, gc03, gc04, gc201, gc202, gc203)"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `gc01` | varchar(10) | **PO 編號** |
| `gc02` | varchar(8) | 預計出貨日 |
| `gc03` | varchar(20) | 目的地 |
| `gc04` | varchar(20) | 產品代碼 |
| `gc05` | float | 批次數量 |
| `gc06` | float | 已出貨數量 |
| `gc08` | char(1) | 結案 (Y/N) |
| `gc09` | varchar(8) | 預計到貨日 |
| `gc10` | varchar(10) | 供應商代碼 |

---

## TGM04 - 採購彙總

### 欄位定義

```yaml
table: tgm04
name: "採購彙總"
records: 12415
total_fields: 10
primary_key: "(gd01, gd02, gd03)"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `gd01` | varchar(10) | **PO 編號** |
| `gd02` | varchar(8) | 預計出貨日 |
| `gd03` | varchar(20) | 目的地 |
| `gd06` | float | 總材積 |
| `gd07` | float | 總淨重 |
| `gd08` | float | 總毛重 |

---

## 採購產生邏輯

### 從訂單到採購

```yaml
trigger: "訂單轉採購"
inputs:
  - "[[tfm02]]": 訂單明細行
  - "[[tem05]]": 訂單專用 BOM

process:
  1. 讀取 [[tfm02]] 訂單項目
  2. 對每個項目,查詢 [[tem05]] 的 BOM
  3. 計算每個元件的採購數量
  4. 依供應商分組 ([[tem05.ee06]])
  5. 為每個供應商建立 [[tgm01]]
  6. 建立含計算數量的 [[tgm02]]
  7. 在 [[tfm05]] 記錄連結
```

### 數量計算

```sql
-- 採購數量計算
Purchase_Qty = Order_Qty * (BOM_Ratio_Num / BOM_Ratio_Denom)

-- SQL 實作
SELECT
    ee06 AS [供應商],
    ee03 AS [元件],
    SUM(CAST(([[tfm02.fb09]] * ee04 / ee05) AS DECIMAL(10,2))) AS [採購數量]
FROM [[tfm02]]
INNER JOIN [[tem05]] ON ee011 = fb01 AND ee02 = fb03
WHERE fb01 = @OrderNo
GROUP BY ee06, ee03
ORDER BY ee06
```

### PO 編號格式

```yaml
pattern: "{PI}-{seq}"
example: "00048-01"
explanation:
  - "00048" = 來源 PI 編號 [[tfm01.fa01]]
  - "01" = 序號 (同一訂單多供應商時)
```

---

## 跨模組整合

### 上游 (接收資料)

```yaml
from_tfm:
  source_tables: ["[[tfm01]]", "[[tfm02]]"]
  link_method:
    - "[[tgm01.ga2301]] = [[tfm01.fa01]]"
    - "[[tgm02.gb2601]] = [[tfm01.fa01]]"
  data_inherited:
    - customer: "[[tfm01.fa04]] -> [[tgm01.ga13]]"
    - destination: "[[tfm01.fa14]] -> [[tgm01.ga15]]"

from_tem05:
  source: "[[tem05]]"
  provides:
    - supplier: "[[tem05.ee06]] -> [[tgm01.ga04]]"
    - component: "[[tem05.ee03]] -> [[tgm02.gb04]]"
    - ratio: "[[tem05.ee04]]/[[tem05.ee05]] -> 數量計算"

from_tcm:
  source: "[[tcm01]]"
  lookup_key: "[[tgm01.ga04]]"
  provides: ["供應商名稱", "地址", "聯絡人"]
```

### 下游 (發送資料)

```yaml
to_thm:
  trigger: "從 PO 建立出貨單"
  data_flow:
    - "[[tgm01]] -> 出貨參照"
    - "[[tgm02]] -> 出貨項目 (直接出貨時)"

to_tlm:
  trigger: "PO 確認/收貨"
  action: "自動在 [[tlm09]] 建立應付帳款"
  data:
    - "[[tgm01.ga01]] -> 應付參照"
    - "[[tgm01.ga04]] -> 供應商"
    - "SUM([[tgm02.gb20]]) -> 應付金額"
```

---

## 追溯查詢

### 追溯 PO 至來源訂單

```sql
-- 查詢 PO 的來源 PI
SELECT
    p.ga01 AS [PO],
    p.ga2301 AS [來源PI],
    o.fa04 AS [客戶],
    o.fa03 AS [訂單日期],
    p.ga04 AS [供應商],
    p.ga03 AS [PO日期]
FROM [[tgm01]] p
INNER JOIN [[tfm01]] o ON o.fa01 = p.ga2301
WHERE p.ga01 = @PONumber
```

### 追溯訂單至所有 PO

```sql
-- 查詢從 PI 產生的所有 PO
SELECT
    o.fa01 AS [PI],
    p.ga01 AS [PO],
    p.ga04 AS [供應商],
    SUM(pd.gb09) AS [總數量],
    SUM(pd.gb20) AS [總金額]
FROM [[tfm01]] o
INNER JOIN [[tgm01]] p ON p.ga2301 = o.fa01
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01
WHERE o.fa01 = @OrderNo
GROUP BY o.fa01, p.ga01, p.ga04
```

### 完整鏈結查詢

```sql
-- 完整的 訂單->採購->元件 追溯
SELECT
    o.fa01 AS [訂單],
    od.fb03 AS [訂單產品],
    od.fb09 AS [訂單數量],
    b.ee03 AS [元件],
    b.ee06 AS [供應商],
    CAST((od.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [需求數量],
    p.ga01 AS [PO],
    pd.gb09 AS [採購數量]
FROM [[tfm01]] o
INNER JOIN [[tfm02]] od ON od.fb01 = o.fa01
LEFT JOIN [[tem05]] b ON b.ee011 = o.fa01 AND b.ee02 = od.fb03
LEFT JOIN [[tgm01]] p ON p.ga2301 = o.fa01 AND p.ga04 = b.ee06
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01 AND pd.gb04 = b.ee03
WHERE o.fa01 = @OrderNo
ORDER BY od.fb02, b.ee07
```

---

## 導覽

- **上一頁**: `./07-tfm.md` (銷售訂單)
- **下一頁**: `./09-thm.md` (出貨單)
- **索引**: `./_index.yaml`
- **概述**: `./00-overview.md`
