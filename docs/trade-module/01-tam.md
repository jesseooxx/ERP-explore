# TAM - 系統設定

```yaml
---
module_id: tam
name_zh: "系統設定"
name_en: "System Settings"
table_range: tam01-tam26
field_prefix: "{varies}"
layer: configuration
scope: global
tables: 26
index: "./_index.yaml"
---
```

## 模組概述

TAM 提供全域系統設定，包括公司資訊、使用者管理、幣別設定及地區資料。這些設定被所有交易模組參照。

---

## 資料表清單

| 資料表 | 用途 | 關鍵欄位 |
|-------|---------|------------|
| tam01 | 公司資訊 | company_code, name, address |
| tam02 | 分公司/部門 | branch_code, dept_name |
| tam03 | 系統旗標 | 功能開關 |
| tam04 | 文件範本 | doc_type, template_path |
| tam05 | 使用者主檔 | user_id, password, permissions |
| tam06 | 使用者群組 | group_id, group_name |
| tam07 | 存取控制 | user_id, module, permission_level |
| tam08 | **幣別主檔** | ha01 (代碼), exchange_rate |
| tam09 | 匯率歷史紀錄 | currency, date, rate |
| tam10 | 銀行主檔 | bank_code, bank_name, swift |
| tam11 | 付款條件 | term_code, days, description |
| tam12 | 出貨方式 | method_code, description |
| tam13-16 | 保留 | - |
| tam17 | **港口/國家** | port_code, country, port_name |
| tam18-20 | 貿易條件 | 國貿條規、定義 |
| tam21-26 | 其他設定 | 各種系統設定 |

---

## 重要資料表

### TAM08 - 幣別主檔

```yaml
table: tam08
purpose: "幣別代碼與匯率"
primary_key: ha01
```

| 欄位 | 類型 | 說明 | 被參照於 |
|-------|------|-------------|---------------|
| `ha01` | varchar(5) | **幣別代碼** (USD, TWD 等) | `[[tfm01.fa19]]`, `[[tgm01.ga06]]`, `[[thm01.ha19]]` |
| `ha02` | varchar(20) | 幣別名稱 | |
| `ha03` | float | 對基準幣匯率 | |
| `ha04` | char(1) | 啟用旗標 | |

### TAM17 - 港口/國家

```yaml
table: tam17
purpose: "港口與國家參考資料"
```

| 欄位 | 類型 | 說明 | 被參照於 |
|-------|------|-------------|---------------|
| port_code | varchar(10) | 港口識別碼 | `[[tfm01.fa11]]`, `[[tfm01.fa14]]` |
| country | varchar(10) | 國家代碼 | |
| port_name | varchar(50) | 港口全名 | |

---

## 跨模組參照

```yaml
provides_to:
  tfm:
    - "[[tam08.ha01]] -> [[tfm01.fa19]] (訂單幣別)"
    - "[[tam17]] -> [[tfm01.fa11]], [[tfm01.fa14]] (港口)"
  tgm:
    - "[[tam08.ha01]] -> [[tgm01.ga06]] (PO 幣別)"
  thm:
    - "[[tam08.ha01]] -> [[thm01.ha19]] (發票幣別)"
  all_modules:
    - "[[tam05]] -> 使用者驗證"
    - "[[tam01]] -> 公司表頭資訊"
```

---

## 導覽

- **下一頁**: `./02-tsm.md` (運作參數)
- **索引**: `./_index.yaml`
- **概述**: `./00-overview.md`
