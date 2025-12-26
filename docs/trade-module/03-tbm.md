# TBM - 客戶主檔

```yaml
---
module_id: tbm
name_zh: "客戶主檔"
name_en: "Customer Master"
table_range: tbm01-tbm23
field_prefix: "b{table_char}{seq}"
layer: master_data
tables: 23
primary_key: "[[tbm01.ba01]]"
index: "./_index.yaml"
---
```

## 模組概述

TBM 管理客戶主檔資料，包括公司資訊、聯絡人、地址及客戶專屬產品設定。主鍵 `[[tbm01.ba01]]` 在所有交易模組中被參照。

---

## 資料表清單

| 資料表 | 用途 | 主鍵 |
|-------|---------|-------------|
| tbm01 | **客戶主檔** | `ba01` |
| tbm02 | 客戶聯絡人 | `(bb01, bb02)` |
| tbm03 | 客戶地址 | `(bc01, bc02)` |
| tbm04 | 客戶銀行資訊 | `(bd01, bd02)` |
| tbm05 | 客戶-產品連結 | `(be01, be02)` |
| tbm06 | 客戶價格層級 | `(bf01, bf02)` |
| tbm07 | 付款歷史 | `(bg01, bg02)` |
| tbm08-10 | 信用管理 | - |
| tbm11-15 | 客戶分類 | - |
| tbm16-20 | 客戶偏好設定 | - |
| tbm21-23 | 保留 | - |

---

## TBM01 - 客戶主檔

### 欄位定義

```yaml
table: tbm01
name: "客戶主檔"
primary_key: ba01
total_fields: ~50
```

| 欄位 | 類型 | 說明 | 被參照於 |
|-------|------|-------------|---------------|
| `ba01` | varchar(10) | **客戶代碼** (主鍵) | `[[tfm01.fa04]]`, `[[tem01.ea02]]`, `[[thm01.ha04]]` |
| `ba02` | varchar(50) | 客戶名稱 | |
| `ba03` | varchar(100) | 地址第一行 | |
| `ba04` | varchar(100) | 地址第二行 | |
| `ba05` | varchar(10) | 國家 | |
| `ba06` | varchar(20) | 電話 | |
| `ba07` | varchar(50) | 電子郵件 | |
| `ba08` | varchar(5) | 幣別偏好 | `[[tam08.ha01]]` |
| `ba09` | varchar(10) | 付款條件 | `[[tam11]]` |
| `ba10` | varchar(10) | 業務代表 | |
| `ba11` | float | 信用額度 | |
| `ba12` | char(1) | 啟用 (Y/N) | |

---

## TBM02 - 客戶聯絡人

```yaml
table: tbm02
name: "客戶聯絡人"
primary_key: "(bb01, bb02)"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `bb01` | varchar(10) | **客戶代碼** -> `[[tbm01.ba01]]` |
| `bb02` | int | 聯絡人序號 |
| `bb03` | varchar(30) | 聯絡人姓名 |
| `bb04` | varchar(30) | 職稱/職位 |
| `bb05` | varchar(20) | 電話 |
| `bb06` | varchar(50) | 電子郵件 |
| `bb07` | char(1) | 主要聯絡人 (Y/N) |

---

## TBM05 - 客戶-產品連結

```yaml
table: tbm05
name: "客戶專屬產品設定"
primary_key: "(be01, be02)"
purpose: "客戶專屬產品代碼、價格"
```

| 欄位 | 類型 | 說明 |
|-------|------|-------------|
| `be01` | varchar(10) | **客戶代碼** -> `[[tbm01.ba01]]` |
| `be02` | varchar(20) | **產品代碼** -> `[[tdm01.da01]]` |
| `be03` | varchar(30) | 客戶產品代碼 |
| `be04` | varchar(50) | 客戶產品名稱 |
| `be05` | float | 客戶專屬價格 |
| `be06` | varchar(5) | 幣別 |

---

## 跨模組參照

### 客戶參照鏈

```yaml
master: "[[tbm01.ba01]]"
referenced_by:
  tem: "[[tem01.ea02]] - 報價單客戶"
  tfm: "[[tfm01.fa04]] - 訂單客戶"
  thm: "[[thm01.ha04]] - 發票客戶"
  tlm: "[[tlm01.customer]] - 應收帳款客戶"
  tgm: "[[tgm01.ga13]] - 間接 (訂單的客戶)"
```

### 資料流程

```
[[tbm01.ba01]] (客戶主檔)
      |
      +---> [[tem01.ea02]] (報價單)
      |           |
      |           v
      +---> [[tfm01.fa04]] (訂單)
      |           |
      |           v
      +---> [[thm01.ha04]] (發票)
                  |
                  v
            [[tlm01]] (應收帳款)
```

---

## 常用查詢

### 查詢客戶與訂單

```sql
-- 查詢啟用客戶及其訂單統計
SELECT
    c.ba01 AS [Customer],
    c.ba02 AS [Name],
    COUNT(o.fa01) AS [Order_Count],
    SUM(o.fa25) AS [Total_Amount]
FROM [[tbm01]] c
LEFT JOIN [[tfm01]] o ON o.fa04 = c.ba01
WHERE c.ba12 = 'Y'  -- 啟用客戶
GROUP BY c.ba01, c.ba02
ORDER BY [Total_Amount] DESC
```

### 查詢客戶產品

```sql
-- 查詢指定客戶的專屬產品設定
SELECT
    c.ba01 AS [Customer],
    cp.be02 AS [Product_Code],
    cp.be03 AS [Customer_PN],
    cp.be05 AS [Customer_Price],
    d.da02 AS [Product_Name]
FROM [[tbm01]] c
INNER JOIN [[tbm05]] cp ON cp.be01 = c.ba01
INNER JOIN [[tdm01]] d ON d.da01 = cp.be02
WHERE c.ba01 = @CustomerCode
```

---

## 導覽

- **上一頁**: `./02-tsm.md` (運作參數)
- **下一頁**: `./04-tcm.md` (供應商主檔)
- **索引**: `./_index.yaml`
