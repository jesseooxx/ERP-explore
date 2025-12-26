# TCM - 供應商主檔

```yaml
---
module_id: tcm
name_zh: "供應商主檔"
name_en: "Supplier Master"
table_range: tcm01-tcm15
field_prefix: "c{table_char}{seq}"
layer: master_data
tables: 15
primary_key: "[[tcm01.ca01]]"
index: "./_index.yaml"
---
```

## 模組概述

TCM 管理供應商主檔資料及供應商-產品關聯。主鍵 `[[tcm01.ca01]]` 連結至採購單和 BOM 定義。

---

## 資料表清單

| 資料表 | 用途 | 主鍵 |
|-------|------|------|
| tcm01 | **供應商主檔** | `ca01` |
| tcm02 | 供應商聯絡人 | `(cb01, cb02)` |
| tcm03 | 供應商地址 | `(cc01, cc02)` |
| tcm04 | 供應商銀行資訊 | `(cd01, cd02)` |
| tcm05 | **供應商-產品關聯** | `(ce010, ce011, ce02, ce04)` |
| tcm06 | 供應商價格歷史 | - |
| tcm07 | 供應商績效 | - |
| tcm08-15 | 保留/其他 | - |

---

## TCM01 - 供應商主檔

### 欄位定義

```yaml
table: tcm01
name: "供應商主檔"
primary_key: ca01
total_fields: ~45
```

| 欄位 | 類型 | 說明 | 被參照於 |
|------|------|------|----------|
| `ca01` | varchar(10) | **供應商代碼** (主鍵) | `[[tgm01.ga04]]`, `[[tem05.ee06]]`, `[[tdm05.de05]]` |
| `ca02` | varchar(50) | 供應商名稱 | |
| `ca03` | varchar(100) | 地址第一行 | |
| `ca04` | varchar(100) | 地址第二行 | |
| `ca05` | varchar(10) | 國家 | |
| `ca06` | varchar(20) | 電話 | |
| `ca07` | varchar(50) | 電子郵件 | |
| `ca08` | varchar(5) | 幣別 | `[[tam08.ha01]]` |
| `ca09` | varchar(10) | 付款條件 | |
| `ca10` | int | 交期(天) | |
| `ca11` | char(1) | 啟用 (Y/N) | |

---

## TCM05 - 供應商-產品關聯

### 欄位定義

```yaml
table: tcm05
name: "供應商-產品關聯"
primary_key: "(ce010, ce011, ce02, ce04)"
purpose: "連結產品與供應商及定價"
```

| 欄位 | 類型 | 說明 |
|------|------|------|
| `ce010` | varchar(10) | **供應商代碼** -> `[[tcm01.ca01]]` |
| `ce011` | varchar(10) | 限定詞 |
| `ce02` | varchar(20) | **產品/零件代碼** -> `[[tdm01.da01]]` |
| `ce03` | varchar(30) | 供應商料號 |
| `ce04` | int | 序號 |
| `ce05` | float | 單價 |
| `ce06` | varchar(5) | 幣別 |
| `ce07` | int | 最小訂購量(MOQ) |
| `ce08` | int | 交期(天) |

---

## 跨模組參照

### 供應商參照鏈

```yaml
master: "[[tcm01.ca01]]"
referenced_by:
  tdm: "[[tdm05.de05]] - 標準 BOM 供應商"
  tem: "[[tem05.ee06]] - 訂單 BOM 供應商"
  tgm: "[[tgm01.ga04]] - 採購單供應商"
  tlm: "[[tlm09.supplier]] - 應付帳款供應商"
```

### 資料流程

```
[[tcm01.ca01]] (供應商主檔)
      |
      +---> [[tdm05.de05]] (標準 BOM)
      |           |
      |           v (建立訂單時複製)
      +---> [[tem05.ee06]] (訂單 BOM)
      |           |
      |           v (產生採購單)
      +---> [[tgm01.ga04]] (採購單)
                  |
                  v (儲存時自動建立)
            [[tlm09]] (應付帳款)
```

---

## 與 BOM 的關係

### 標準 BOM (tdm05)

```yaml
table: "[[tdm05]]"
pk: "(de01, de02)"
supplier_field: "[[tdm05.de05]]"
usage: "每個零件的預設供應商"
```

### 訂單 BOM (tem05)

```yaml
table: "[[tem05]]"
pk: "(ee011, ee02, ee03)"
supplier_field: "[[tem05.ee06]]"
usage: "訂單專屬供應商 (可能與標準不同)"
trigger: "建立訂單時從 [[tdm05]] 複製"
```

---

## 常用查詢

### 取得供應商及其產品

```sql
SELECT
    s.ca01 AS [供應商],
    s.ca02 AS [名稱],
    sp.ce02 AS [產品],
    sp.ce05 AS [價格],
    sp.ce08 AS [交期]
FROM [[tcm01]] s
INNER JOIN [[tcm05]] sp ON sp.ce010 = s.ca01
WHERE s.ca11 = 'Y'  -- 啟用的供應商
ORDER BY s.ca01, sp.ce02
```

### 取得供應商採購歷史

```sql
SELECT
    s.ca01 AS [供應商],
    s.ca02 AS [名稱],
    COUNT(p.ga01) AS [採購單數],
    SUM(p.ga37) AS [總金額]
FROM [[tcm01]] s
LEFT JOIN [[tgm01]] p ON p.ga04 = s.ca01
WHERE s.ca11 = 'Y'
GROUP BY s.ca01, s.ca02
ORDER BY [總金額] DESC
```

### 查詢零件的供應商

```sql
SELECT
    sp.ce010 AS [供應商],
    s.ca02 AS [供應商名稱],
    sp.ce03 AS [供應商料號],
    sp.ce05 AS [價格],
    sp.ce07 AS [最小訂購量],
    sp.ce08 AS [交期]
FROM [[tcm05]] sp
INNER JOIN [[tcm01]] s ON s.ca01 = sp.ce010
WHERE sp.ce02 = @ComponentCode
ORDER BY sp.ce05  -- 依價格排序
```

---

## 導覽

- **上一篇**: `./03-tbm.md` (客戶主檔)
- **下一篇**: `./05-tdm.md` (產品主檔)
- **索引**: `./_index.yaml`
