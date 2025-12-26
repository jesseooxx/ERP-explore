# TFM - 銷售訂單模組 (PI)

```yaml
---
module_id: tfm
name_zh: "銷售訂單"
name_en: "Sales Order / Proforma Invoice (PI)"
table_range: tfm01-tfm12
field_prefix: "f{table_char}{seq}"
primary_key: "[[tfm01.fa01]]"
flow_position: 2
receives_from: ["[[tem01]]", "[[tbm01]]", "[[tdm01]]"]
sends_to: ["[[tgm01]]", "[[thm01]]"]
index: "./_index.yaml"
---
```

## 模組概述

TFM 模組處理銷售訂單 (PI - Proforma Invoice),這是連結客戶需求與採購及出貨的核心交易單據。

**流程位置:**
```
[[tem01]] (報價單) --> [[tfm01]] (訂單) --> [[tgm01]] (採購單)
                                       --> [[thm01]] (出貨單)
```

---

## 資料表清單

| 資料表 | 記錄數 | 用途 | 主鍵 |
|-------|---------|---------|-------------|
| tfm01 | 5,293 | 訂單主檔 | `fa01` |
| tfm02 | 20,488 | 訂單明細 | `(fb01, fb02)` |
| tfm03 | 23,446 | 出貨排程明細 | `(fc01, fc02, fc031..., fc04)` |
| tfm04 | 8,306 | 出貨排程彙總 | `(fd01, fd02, fd03)` |
| tfm05 | 27,582 | 訂單-採購連結 | `(fe01, fe03, fe04, fe07, fe25)` |
| tfm09-12 | 0 | 報關資料 (未使用) | 各異 |

---

## TFM01 - 訂單主檔

### 欄位定義

```yaml
table: tfm01
name: "銷售訂單主檔"
records: 5293
total_fields: 99
primary_key: fa01
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `fa01` | varchar(10) | NO | **PI 訂單編號** | 主鍵 |
| `fa02` | char(1) | YES | 訂單類型 (I=進出口) | |
| `fa03` | varchar(8) | YES | 訂單日期 (YYYYMMDD) | |
| `fa04` | varchar(10) | YES | **客戶代碼** | `[[tbm01.ba01]]` |
| `fa05` | varchar(3) | YES | 業務員代碼 | |
| `fa07` | varchar(30) | YES | 聯絡人 | |
| `fa08` | varchar(20) | YES | 客戶訂單編號 | |
| `fa09` | char(1) | YES | 狀態 | |
| `fa11` | varchar(20) | YES | 裝貨港 | `[[tam17]]` |
| `fa14` | varchar(20) | YES | 目的港 | `[[tam17]]` |
| `fa17` | varchar(6) | YES | 貿易條件 (FOB/CIF) | `[[tam13]]` |
| `fa19` | varchar(5) | YES | **幣別** | `[[tam08.ha01]]` |
| `fa20` | float | YES | 匯率 | |
| `fa32` | varchar(8) | YES | 預計出貨日期 | |
| `fa37` | float | YES | 總金額 | |
| `fa63` | char(1) | YES | **結案旗標** (Y/N) | |
| `fa64` | char(1) | YES | 取消旗標 (Y/N) | |

### 關鍵關聯

```yaml
outbound_references:
  - field: "fa04"
    target: "[[tbm01.ba01]]"
    description: "客戶主檔"
  - field: "fa19"
    target: "[[tam08.ha01]]"
    description: "幣別代碼"

inbound_references:
  - source: "[[tfm02.fb01]]"
    description: "訂單明細行"
  - source: "[[tfm03.fc01]]"
    description: "出貨排程"
  - source: "[[tgm01.ga2301]]"
    description: "產生的採購單"
  - source: "[[tem05.ee011]]"
    description: "訂單專用 BOM"
```

---

## TFM02 - 訂單明細

### 欄位定義

```yaml
table: tfm02
name: "銷售訂單明細"
records: 20488
total_fields: 67
primary_key: "(fb01, fb02)"
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `fb01` | varchar(10) | NO | **PI 編號** | `[[tfm01.fa01]]` |
| `fb02` | float | NO | **行序號** | 主鍵組成 |
| `fb03` | varchar(20) | YES | **產品代碼** | `[[tdm01.da01]]` |
| `fb06` | varchar(30) | YES | 產品名稱第1行 | |
| `fb07` | varchar(30) | YES | 產品名稱第2行 | |
| `fb09` | float | YES | **訂單數量** | |
| `fb10` | varchar(6) | YES | 單位 | |
| `fb11` | float | YES | 單價 | |
| `fb12` | float | YES | 行金額 | |
| `fb13` | varchar(10) | YES | 供應商代碼 | `[[tcm01.ca01]]` |
| `fb22` | float | YES | 內包裝數量 | |
| `fb23` | float | YES | **外箱裝數量** | 用於材積計算 |
| `fb25` | float | YES | **每箱材積** | 用於材積計算 |
| `fb53` | char(1) | YES | 結案旗標 | |

### BOM 複製觸發

```sql
-- 當 tfm02 新增時,複製標準 BOM 至訂單 BOM
ON INSERT tfm02:
  INSERT INTO [[tem05]] (ee010, ee011, ee02, ee03, ee04, ee05, ee06, ee07, ee08, ee10)
  SELECT 'S', NEW.fb01, de01, de02, de03, de04, de05, de06, de07, de09
  FROM [[tdm05]]
  WHERE de01 = NEW.fb03 AND de18 = 'Y'
```

---

## TFM03 - 出貨排程明細

### 欄位定義

```yaml
table: tfm03
name: "出貨排程明細"
records: 23446
total_fields: 15
primary_key: "(fc01, fc02, fc031, fc032, fc033, fc034, fc04)"
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `fc01` | varchar(10) | NO | **PI 編號** | `[[tfm01.fa01]]` |
| `fc02` | varchar(8) | NO | **預計出貨日** (YYYYMMDD) | 主鍵組成 |
| `fc031` | varchar(20) | NO | **目的港** | 主鍵組成 |
| `fc032-034` | varchar | NO | (保留欄位) | 主鍵組成 |
| `fc04` | varchar(20) | NO | **產品代碼** | `[[tfm02.fb03]]` |
| `fc05` | float | YES | **排程數量** | |
| `fc06` | float | YES | **已出貨數量** | |
| `fc08` | char(1) | YES | **結案** (Y/N) | |
| `fc09` | varchar(8) | YES | 原始預計出貨日 | |
| `fc10` | varchar(10) | YES | 客戶代碼 | |

### 排程邏輯

```yaml
constraints:
  - "依產品加總 SUM(fc05) <= [[tfm02.fb09]]"
  - "fc06 <= fc05"
  - "當 fc06 >= fc05 時 fc08 = 'Y'"

aggregation:
  - target: "[[tfm04]]"
    group_by: ["fc01", "fc02", "fc031"]
    sum_fields: ["fc05"]
```

---

## TFM04 - 出貨排程彙總

### 欄位定義

```yaml
table: tfm04
name: "出貨排程彙總"
records: 8306
total_fields: 10
primary_key: "(fd01, fd02, fd03)"
```

| 欄位 | 類型 | 可空 | 說明 |
|-------|------|------|-------------|
| `fd01` | varchar(10) | NO | **PI 編號** |
| `fd02` | varchar(8) | NO | **預計出貨日** |
| `fd03` | varchar(20) | NO | **目的地** |
| `fd04` | varchar(30) | YES | 船名/航次 |
| `fd06` | float | YES | **總材積** |
| `fd07` | float | YES | 總淨重 |
| `fd08` | float | YES | **總箱數** |

### 計算方式

```sql
-- 材積計算
fd06 = SUM(fc05 * ([[tfm02.fb25]] / [[tfm02.fb23]]))
     WHERE tfm02.fb01 = fc01 AND tfm02.fb03 = fc04
```

---

## TFM05 - 訂單-採購連結

### 欄位定義

```yaml
table: tfm05
name: "訂單-採購選擇"
records: 27582
total_fields: 30
primary_key: "(fe01, fe03, fe04, fe07, fe25)"
```

| 欄位 | 類型 | 可空 | 說明 | 參照 |
|-------|------|------|-------------|-----------|
| `fe01` | varchar(10) | NO | **PI 編號** | `[[tfm01.fa01]]` |
| `fe02` | float | YES | 行序號 | |
| `fe03` | varchar(20) | NO | **產品代碼** | `[[tfm02.fb03]]` |
| `fe04` | varchar(10) | NO | **供應商代碼** | `[[tcm01.ca01]]` |
| `fe06` | float | YES | **訂單數量** | |
| `fe07` | varchar(5) | NO | **幣別** | |
| `fe08` | float | YES | 單價 | |
| `fe12` | varchar(10) | YES | **PO 編號** | `[[tgm01.ga01]]` |

### 用途

記錄每個訂單項目的供應商選擇,用於採購單產生時使用。

---

## 跨模組整合

### 上游 (接收資料)

```yaml
from_tem:
  trigger: "報價確認"
  data_flow:
    - "[[tem01]] -> [[tfm01]]"
    - "[[tem02]] -> [[tfm02]]"
    - "[[tem05]] 保留並更新 ee011"

from_tbm:
  field: "[[tfm01.fa04]]"
  source: "[[tbm01.ba01]]"
  brings: ["客戶名稱", "地址", "聯絡人"]

from_tdm:
  field: "[[tfm02.fb03]]"
  source: "[[tdm01.da01]]"
  brings: ["產品名稱", "規格", "包裝"]
  triggers: "BOM 複製至 [[tem05]]"
```

### 下游 (發送資料)

```yaml
to_tgm:
  trigger: "訂單轉採購"
  link_fields:
    - "[[tgm01.ga2301]] = [[tfm01.fa01]]"
    - "[[tgm02.gb2601]] = [[tfm01.fa01]]"
  calculation: "依 BOM 比例計算採購數量"

to_thm:
  trigger: "建立出貨單"
  data_flow:
    - "[[tfm01.fa04]] -> [[thm01.ha04]]"
    - "[[tfm02]] -> [[thm02]]"
    - "[[tfm03]] -> 出貨排程參照"

to_tem05:
  trigger: "[[tfm02]] 新增時"
  action: "從 [[tdm05]] 複製 BOM"
  key: "ee011 = [[tfm01.fa01]]"
```

---

## 常用查詢

### 查詢訂單及明細

```sql
SELECT
    t1.fa01 AS [PI],
    t1.fa04 AS [客戶],
    t1.fa03 AS [日期],
    t2.fb02 AS [行號],
    t2.fb03 AS [產品],
    t2.fb09 AS [數量],
    t2.fb11 AS [單價],
    t2.fb12 AS [金額]
FROM [[tfm01]] t1
INNER JOIN [[tfm02]] t2 ON t2.fb01 = t1.fa01
WHERE t1.fa01 = @OrderNo
ORDER BY t2.fb02
```

### 查詢訂單及 BOM

```sql
SELECT
    t1.fa01, t2.fb03, t2.fb09,
    b.ee03 AS [元件],
    CAST((t2.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [元件數量],
    b.ee06 AS [供應商]
FROM [[tfm01]] t1
INNER JOIN [[tfm02]] t2 ON t2.fb01 = t1.fa01
LEFT JOIN [[tem05]] b ON b.ee011 = t1.fa01 AND b.ee02 = t2.fb03
WHERE t1.fa01 = @OrderNo
```

---

## 導覽

- **上一頁**: `./06-tem.md` (報價單)
- **下一頁**: `./08-tgm.md` (採購單)
- **索引**: `./_index.yaml`
- **概述**: `./00-overview.md`
