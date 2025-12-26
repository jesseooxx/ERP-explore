# THM - 出貨模組 (INV/PKG)

```yaml
---
module_id: thm
name_zh: "出貨/發票/裝箱"
name_en: "Shipment / Invoice / Packing"
table_range: thm01-thm15
field_prefix: "h{table_char}{seq}"
primary_key: "[[thm01.ha01]]"
flow_position: 4
receives_from: ["[[tfm01]]", "[[tfm02]]", "[[tfm03]]", "[[tgm01]]"]
sends_to: ["[[tlm01]]", "[[trm01]]", "[[tjm01]]"]
outputs: ["INVOICE", "PACKING_LIST", "SHIPPING_MARK"]
index: "./_index.yaml"
---
```

## 模組概述

THM 模組是最終交易步驟,產生 INVOICE、PACKING LIST 和 SHIPPING MARK 文件。它會自動觸發應收帳款的建立。

**流程位置:**
```
[[tfm01]] (訂單) + [[tgm01]] (採購單) --> [[thm01]] (出貨單)
                                              |
                                              +--> INVOICE
                                              +--> PACKING LIST
                                              +--> SHIPPING MARK
                                              +--> [[tlm01]] (應收帳款)
```

---

## 資料表清單

| 資料表 | 記錄數 | 用途 | 主鍵 |
|-------|---------|---------|-------------|
| thm01 | 3,697 | 出貨/發票主檔 | `ha01` |
| thm02 | 11,262 | PI 項目 | `(hb01, hb02)` |
| thm03 | 33,602 | 裝箱項目 | `(hc01, hc02, hc18)` |
| thm04 | 25,338 | 發票項目/成本 | `(hd011, hd012, ...)` |
| thm05 | 34,829 | 元件成本 | `(he01-he09)` |
| thm06 | - | **SHIPPING MARK** | `(hf01, ...)` |
| thm07 | 417,961 | 項目子描述 | `(hg01-hg05)` |
| thm08 | 3,395 | 額外費用 | `(hh010, hh011, hh02)` |

---

## THM01 - 出貨/發票主檔

### 欄位定義

```yaml
table: thm01
name: "出貨/發票主檔"
records: 3697
total_fields: 141
primary_key: ha01
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `ha01` | varchar(10) | NO | **發票/出貨編號** | 主鍵 |
| `ha02` | char(1) | YES | 類型 (I=發票) | |
| `ha03` | varchar(8) | YES | 出貨日期 | |
| `ha04` | varchar(10) | YES | **客戶代碼** | `[[tbm01.ba01]]` |
| `ha05` | varchar(3) | YES | 部門 | |
| `ha19` | varchar(5) | YES | **幣別** | `[[tam08.ha01]]` |
| `ha81` | varchar(3) | NO | 運送方式 | |
| `ha83-87` | varchar | NO | 發貨人/收貨人資訊 | |

### 文件類型

```yaml
document_codes:
  I: "發票"
  T: "發票備註"
  5: "裝箱備註"
  8: "出貨通知備註"
  B: "出貨通知單備註"
```

---

## THM02 - PI 項目 (來自訂單的發票行)

### 欄位定義

```yaml
table: thm02
name: "出貨 PI 項目"
records: 11262
total_fields: 13
primary_key: "(hb01, hb02)"
```

| 欄位 | 類型 | 說明 | 參照 |
|-------|------|-------------|-----------|
| `hb01` | varchar(10) | **發票編號** | `[[thm01.ha01]]` |
| `hb02` | varchar(10) | **產品代碼** | `[[tfm02.fb03]]` |
| `hb03` | varchar(2) | 單位 | |
| `hb06-12` | float | 數量及價格欄位 | |

---

## THM03 - 裝箱項目

### 欄位定義

```yaml
table: thm03
name: "裝箱項目"
records: 33602
total_fields: 38
primary_key: "(hc01, hc02, hc18)"
purpose: "PACKING LIST 明細"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `hc01` | varchar(10) | **發票編號** |
| `hc02` | varchar(10) | **產品代碼** |
| `hc03` | varchar(20) | 項目描述 |
| `hc04-17` | various | 規格、尺寸 |
| `hc18` | float | **序號** |

### PACKING LIST 內容

```yaml
packing_list_fields:
  box_number: "來自序號"
  product: "[[thm03.hc02]]"
  description: "[[thm03.hc03]]"
  quantity: "每箱數量"
  net_weight: "公斤"
  gross_weight: "公斤"
  dimensions: "長 x 寬 x 高"
  cbm: "計算值"
```

---

## THM04 - 發票項目/成本分析

### 欄位定義

```yaml
table: thm04
name: "發票項目"
records: 25338
total_fields: 22
primary_key: "(hd011, hd012, hd032, hd033, hd034, hd02, hd03)"
purpose: "含成本明細的發票行項目"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `hd011` | varchar(10) | 發票編號 |
| `hd012` | varchar(10) | 產品代碼 |
| `hd02-03` | varchar | 成本類別 |
| `hd11-17` | float | 成本值 (材料、人工、費用) |

---

## THM05 - 元件成本

### 欄位定義

```yaml
table: thm05
name: "元件成本"
records: 34829
total_fields: 11
primary_key: "(he01-he09)"
purpose: "BOM 元件成本追蹤"
```

將發票項目連結至其 BOM 元件以進行成本分析。

---

## THM06 - SHIPPING MARK

### 欄位定義

```yaml
table: thm06
name: "SHIPPING MARK"
total_fields: 7
purpose: "SHIPPING MARK 範本及內容"
```

| 欄位 | 說明 |
|-------|-------------|
| `hf01-03` | 發票 + 識別碼 |
| `hf04` | 嘜頭類型 |
| `hf05-07` | 嘜頭內容行 |

### SHIPPING MARK 自動填入

```yaml
auto_fill_fields:
  - "P/O NO." -> 來自 [[tfm01.fa08]] 的客戶訂單編號
  - "C/NO" -> 箱號 (序號)
  - "Customer PO" -> [[tfm01.fa08]]
  - "MADE IN" -> "TAIWAN" 或設定值
```

---

## THM07 - 項目子描述

### 欄位定義

```yaml
table: thm07
name: "項目子描述"
records: 417961
total_fields: 7
primary_key: "(hg01, hg02, hg03, hg04, hg05)"
purpose: "發票的詳細項目描述"
```

THM 最大的資料表 - 儲存多行產品描述。

---

## THM08 - 額外費用

### 欄位定義

```yaml
table: thm08
name: "額外費用"
records: 3395
total_fields: 5
primary_key: "(hh010, hh011, hh02)"
purpose: "運費、保險費、其他費用"
```

| 欄位 | 說明 |
|-------|-------------|
| `hh010` | 類型 (I=發票) |
| `hh011` | 發票編號 |
| `hh02` | 序號 |
| `hh03` | 費用說明 |
| `hh04` | 金額 |

---

## 文件產生

### INVOICE 結構

```yaml
invoice_composition:
  header: "[[thm01]]"
    - invoice_no: "ha01"
    - date: "ha03"
    - customer: "ha04"
    - currency: "ha19"

  line_items: "[[thm02]] + [[thm04]]"
    - product: "hb02"
    - quantity: "hb06"
    - unit_price: "hb11"
    - amount: "hb12"

  charges: "[[thm08]]"
    - freight
    - insurance
    - discount

  total: "SUM(line_items) + SUM(charges)"
```

### PACKING LIST 結構

```yaml
packing_list_composition:
  header: "[[thm01]]"
    - invoice_no: "ha01"
    - vessel: "來自排程"
    - destination: "來自訂單"

  items: "[[thm03]]"
    - box_no: "序號"
    - product: "hc02"
    - description: "hc03"
    - qty_per_box: "hc##"
    - n.w.: "淨重"
    - g.w.: "毛重"
    - dimensions: "長 x 寬 x 高"
    - cbm: "計算值"

  totals:
    - total_boxes
    - total_n.w.
    - total_g.w.
    - total_cbm
```

### SHIPPING MARK 結構

```yaml
mark_composition:
  source: "[[thm06]]"
  template_fields:
    - customer_name
    - destination
    - po_number
    - carton_range: "C/NO 1-100"
    - made_in: "TAIWAN"
```

---

## 自動產生應收帳款

### 觸發條件

```yaml
trigger:
  event: "[[thm01]] 儲存 (已確認)"
  condition: "ha02 = 'I' (發票類型)"

action:
  target: "[[tlm01]]"
  mapping:
    - "tlm01.invoice_no = [[thm01.ha01]]"
    - "tlm01.customer = [[thm01.ha04]]"
    - "tlm01.amount = 計算總額"
    - "tlm01.currency = [[thm01.ha19]]"
    - "tlm01.doc_type = 'I'"
```

### 應收帳款計算

```sql
AR_Amount = SUM([[thm04.line_amount]])
          + SUM([[thm08.charges]])
          - Discount
```

---

## 跨模組整合

### 上游 (接收資料)

```yaml
from_tfm:
  source: "[[tfm01]], [[tfm02]], [[tfm03]]"
  data_flow:
    - "[[tfm01.fa04]] -> [[thm01.ha04]] (客戶)"
    - "[[tfm02.fb03]] -> [[thm02.hb02]] (產品)"
    - "[[tfm03]] -> 出貨排程參照"

from_tgm:
  source: "[[tgm01]], [[tgm02]]"
  usage: "從供應商出貨時參照"

from_tdm:
  source: "[[tdm08]]"
  provides: "[[thm03]] 的預設包裝規格"

from_tqm:
  source: "[[tqm26]]"
  provides: "尺寸/顏色明細"
  source: "[[tqm19]]/[[tqm20]]"
  provides: "客戶專屬嘜頭範本"
```

### 下游 (發送資料)

```yaml
to_tlm:
  trigger: "發票確認"
  action: "建立應收帳款記錄"
  target: "[[tlm01]]"

to_trm:
  trigger: "出貨完成"
  action: "更新出貨分析"
  target: "[[trm01]], [[trm02]]"

to_tjm:
  trigger: "回報品質問題"
  action: "建立索賠記錄"
  target: "[[tjm01]]"

to_tmm:
  trigger: "期末統計"
  action: "彙總至統計表"
  target: "[[tmm05]], [[tmm06]], [[tmm24]], [[tmm25]]"
```

---

## 常用查詢

### 查詢發票及明細

```sql
SELECT
    h1.ha01 AS [發票],
    h1.ha03 AS [日期],
    h1.ha04 AS [客戶],
    h2.hb02 AS [產品],
    h2.hb06 AS [數量],
    h4.hd11 AS [金額]
FROM [[thm01]] h1
INNER JOIN [[thm02]] h2 ON h2.hb01 = h1.ha01
LEFT JOIN [[thm04]] h4 ON h4.hd011 = h1.ha01 AND h4.hd012 = h2.hb02
WHERE h1.ha01 = @InvoiceNo
```

### 查詢 PACKING LIST

```sql
SELECT
    h1.ha01 AS [發票],
    h3.hc18 AS [箱號],
    h3.hc02 AS [產品],
    h3.hc03 AS [描述],
    h3.net_weight,
    h3.gross_weight,
    h3.cbm
FROM [[thm01]] h1
INNER JOIN [[thm03]] h3 ON h3.hc01 = h1.ha01
WHERE h1.ha01 = @InvoiceNo
ORDER BY h3.hc18
```

### 追溯發票至訂單

```sql
SELECT
    h1.ha01 AS [發票],
    h1.ha04 AS [客戶],
    t1.fa01 AS [PI],
    t1.fa03 AS [訂單日期],
    h1.ha03 AS [出貨日期]
FROM [[thm01]] h1
INNER JOIN [[tfm01]] t1 ON t1.fa04 = h1.ha04
WHERE h1.ha01 = @InvoiceNo
```

---

## 導覽

- **上一頁**: `./08-tgm.md` (採購單)
- **下一頁**: 返回 `./00-overview.md`
- **輔助模組**: `./_auxiliary.md` (tlm, trm, tjm)
- **索引**: `./_index.yaml`
