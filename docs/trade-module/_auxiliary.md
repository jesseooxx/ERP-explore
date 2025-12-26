# T 模組輔助系統參考

```yaml
---
id: t-auxiliary
version: "1.0"
updated: "2025-12-26"
type: reference-bundle
scope: auxiliary-modules
modules: [tlm, tqm, trm, tjm, tpm, tnm, tmm, tam, tsm]
related_docs:
  - path: "./00-overview.md"
    rel: "parent"
  - path: "./_index.yaml"
    rel: "index"
---
```

## 目的

本文件整合所有 T 模組輔助子系統供 AI 參考使用。
這些模組支援主要業務流程 (tem->tfm->tgm->thm)，但不屬於
核心交易路徑的一部分。

---

## 模組登錄

```json
{
  "auxiliary_modules": {
    "financial": {
      "tlm": {"tables": 20, "purpose": "應收應付帳款", "triggers_from": ["thm", "tgm"]},
      "tmm": {"tables": 30, "purpose": "統計報表", "aggregates_from": ["tfm", "tgm", "thm"]}
    },
    "operational": {
      "tqm": {"tables": 26, "purpose": "規格催貨型錄", "supports": ["tdm", "thm"]},
      "trm": {"tables": 2, "purpose": "出貨分析", "analyzes": ["thm"]},
      "tjm": {"tables": 2, "purpose": "索賠爭議", "triggered_by": ["thm"]},
      "tpm": {"tables": 2, "purpose": "拋轉追蹤", "tracks": ["tfm->tgm", "tgm->thm"]},
      "tnm": {"tables": 4, "purpose": "歷史歸檔", "archives": ["tfm", "tgm", "thm"]}
    },
    "configuration": {
      "tam": {"tables": 26, "purpose": "系統設定", "scope": "全域"},
      "tsm": {"tables": 15, "purpose": "運作參數", "scope": "模組"}
    }
  }
}
```

---

## 1. TLM - 帳款管理 (20 個資料表)

### 1.1 模組定義
```yaml
module_id: tlm
name_zh: "帳款管理"
name_en: "Accounts Receivable/Payable"
table_range: tlm01-tlm20
field_prefix: "l{table_seq}{field_seq}"  # 例如 la01, lb01
```

### 1.2 資料表分類
| 資料表 | 用途 | 觸發來源 | 關鍵欄位 |
|-------|---------|--------------|------------|
| tlm01-08 | 應收帳款 (AR) | `[[thm01]]` 儲存時 | 客戶、發票號、金額、幣別 |
| tlm09-14 | 應付帳款 (AP) | `[[tgm01]]` 儲存時 | 供應商、採購單號、金額、幣別 |
| tlm15-16 | 信用狀結算 | 手動 | 信用狀號、銀行、押匯金額 |
| tlm17-20 | 雜項/匯款 | 手動 | 匯款銀行、匯款日期 |

### 1.3 自動產生規則
```
觸發條件: [[thm01]] INSERT/UPDATE (ha63='saved')
動作:     INSERT INTO tlm01 (
           invoice_no = [[thm01.ha01]],
           customer   = [[thm01.ha04]],
           amount     = SUM([[thm02.hb12]]),
           currency   = [[thm01.ha19]]
         )

觸發條件: [[tgm01]] INSERT/UPDATE (ga63='saved')
動作:     INSERT INTO tlm09 (
           po_no      = [[tgm01.ga01]],
           supplier   = [[tgm01.ga04]],
           amount     = SUM([[tgm02.gb20]]),
           currency   = [[tgm01.ga06]]
         )
```

### 1.4 交叉參照
- `[[tlm01.customer]]` -> `[[tbm01.ba01]]`
- `[[tlm01.invoice_no]]` -> `[[thm01.ha01]]`
- `[[tlm09.supplier]]` -> `[[tcm01.ca01]]`
- `[[tlm09.po_no]]` -> `[[tgm01.ga01]]`

---

## 2. TQM - 規格/催貨/型錄 (26 個資料表)

### 2.1 模組定義
```yaml
module_id: tqm
name_zh: "規格/催貨/型錄"
name_en: "Specifications, Expediting, Catalog"
table_range: tqm01-tqm26
field_prefix: "q{table_seq}{field_seq}"
```

### 2.2 功能群組
| 群組 | 資料表 | 用途 |
|-------|--------|---------|
| 催貨 | tqm01-03 | 依 PI 及 PO 進行交貨追蹤 |
| 材料規格 | tqm04-05 | 材料屬性與成本分析 |
| 預排出貨 | tqm06-07 | 出貨預先排程 |
| 品項分類 | tqm08-09 | 產品分類 |
| 出貨申請 | tqm15-17 | 出貨申請單 |
| 型錄/款式 | tqm19-22 | 產品型錄與款式定義 |
| 規格品項 | tqm23-24 | 規格品項明細 |
| 尺寸/顏色 | tqm25-26 | 尺寸與顏色資料 |

### 2.3 裝箱單相關
```yaml
packing_sources:
  - table: "[[tqm26]]"
    provides: [尺寸, 顏色, 尺寸規格]
    used_by: "[[thm03]]"
  - table: "[[tqm19]]/[[tqm20]]"
    provides: [客戶專屬型錄]
    used_by: "[[thm06]]"  # 嘜頭
```

### 2.4 交叉參照
- `[[tqm04.material]]` -> `[[tdm01.da01]]`
- `[[tqm01.sc_no]]` -> `[[tfm01.fa01]]`
- `[[tqm03.po_no]]` -> `[[tgm01.ga01]]`

---

## 3. TMM - 統計報表 (30 個資料表)

### 3.1 模組定義
```yaml
module_id: tmm
name_zh: "統計報表"
name_en: "Statistics and Reporting"
table_range: tmm01-tmm26 + logs
field_prefix: "m{table_seq}{field_seq}"
```

### 3.2 關鍵統計資料表
| 資料表 | 記錄數 | 維度 | 用途 |
|-------|---------|------------|---------|
| tmm01 | 719,881 | 使用者、日期、操作 | 操作日誌 |
| tmm03 | 1,065,120 | 產品、客戶、期間 | 銷售統計 |
| tmm13 | 1,111,548 | 客戶、期間、幣別 | 應收帳款統計 |
| tmm24 | 533,088 | 客戶、期間 | 客戶銷售 |
| tmm25 | 610,464 | 產品、期間 | 產品銷售 |

### 3.3 資料來源
```yaml
aggregation_sources:
  tmm02-06: ["[[tfm01]]", "[[tfm02]]", "[[tgm01]]", "[[tgm02]]", "[[thm01]]", "[[thm02]]"]
  tmm13: ["[[tlm01]]"]
  tmm24: ["[[thm01]]", "[[thm02]]", "依 [[tbm01.ba01]] 分組"]
  tmm25: ["[[thm01]]", "[[thm02]]", "依 [[tdm01.da01]] 分組"]
```

---

## 4. TRM - 出貨分析 (2 個資料表)

### 4.1 模組定義
```yaml
module_id: trm
name_zh: "出貨分析"
name_en: "Shipment Analysis"
table_range: trm01-trm02
```

### 4.2 資料表
| 資料表 | 用途 | 維度 |
|-------|---------|------------|
| trm01 | 客戶出貨分析 | 客戶 x 產品 x 期間 |
| trm02 | 產品出貨分析 | 產品 x 客戶 x 期間 |

### 4.3 資料來源
- 彙總自 `[[thm01]]` 及 `[[thm02]]`

---

## 5. TJM - 索賠管理 (2 個資料表)

### 5.1 模組定義
```yaml
module_id: tjm
name_zh: "索賠管理"
name_en: "Claims and Disputes"
table_range: tjm01-tjm02
```

### 5.2 資料表
| 資料表 | 用途 | 觸發來源 |
|-------|---------|--------------|
| tjm01 | 索賠主檔 | 出貨後品質問題 |
| tjm02 | 索賠明細 | 品項級索賠記錄 |

### 5.3 交叉參照
- `[[tjm01.invoice_no]]` -> `[[thm01.ha01]]`
- `[[tjm01.customer]]` -> `[[tbm01.ba01]]`

---

## 6. TPM - 拋轉追蹤 (2 個資料表)

### 6.1 模組定義
```yaml
module_id: tpm
name_zh: "拋轉記錄"
name_en: "Transfer Tracking"
table_range: tpm03-tpm04
```

### 6.2 資料表
| 資料表 | 追蹤內容 | 來源 -> 目標 |
|-------|--------|------------|
| tpm03 | 訂單轉採購 | `[[tfm01]]` -> `[[tgm01]]` |
| tpm04 | 採購轉出貨 | `[[tgm01]]` -> `[[thm01]]` |

### 6.3 對應結構
```yaml
transfer_record:
  tpm03:
    source_doc: "[[tfm01.fa01]]"
    target_doc: "[[tgm01.ga01]]"
    source_line: "[[tfm02.fb02]]"
    target_line: "[[tgm02.gb02]]"
    transfer_date: "YYYYMMDD"
```

---

## 7. TNM - 歷史歸檔 (4 個資料表)

### 7.1 模組定義
```yaml
module_id: tnm
name_zh: "歷史歸檔"
name_en: "History Archive"
table_range: tnm01-tnm04
```

### 7.2 資料表
| 資料表 | 歸檔來源 | 觸發條件 |
|-------|---------------|-------------------|
| tnm01 | `[[tfm01]]` | 訂單完成 (fa63='Y') |
| tnm02 | `[[tfm02]]` | 訂單明細歸檔 |
| tnm03 | `[[tgm01]]` | 採購完成 |
| tnm04 | `[[tgm02]]` | 採購明細歸檔 |

---

## 8. TAM - 系統設定 (26 個資料表)

### 8.1 模組定義
```yaml
module_id: tam
name_zh: "系統設定"
name_en: "System Settings"
table_range: tam01-tam26
field_prefix: "{不固定}"
```

### 8.2 關鍵設定資料表
| 資料表 | 用途 | 使用模組 |
|-------|---------|---------|
| tam01 | 公司資訊 | 所有模組 |
| tam05-07 | 使用者/權限 | 登入、存取控制 |
| tam08-09 | 幣別/匯率 | `[[tfm01.fa19]]`, `[[tgm01.ga06]]`, `[[thm01.ha19]]` |
| tam17 | 港口/國家 | `[[tfm01.fa11]]`, `[[tfm01.fa14]]` |

---

## 9. TSM - 運作參數 (15 個資料表)

### 9.1 模組定義
```yaml
module_id: tsm
name_zh: "運作參數"
name_en: "Runtime Parameters"
table_range: tsm01-tsm13
```

### 9.2 關鍵參數資料表
| 資料表 | 用途 | 使用範例 |
|-------|---------|---------------|
| tsm01 | 系統啟動參數 | CBM/CUFT 換算 (IC15=35.315) |
| tsm03 | 單位換算 | PCS <-> BOX <-> PALLET |
| tsm04 | 報表格式 | 發票、裝箱單樣板 |
| tsm10 | 自動編號規則 | 單據號碼產生 |

---

## 跨模組相依圖

```
                    +---------+
                    |   tam   | (全域設定)
                    |   tsm   | (運作參數)
                    +----+----+
                         |
    +--------------------+--------------------+
    |                    |                    |
    v                    v                    v
+-------+          +-------+           +-------+
|  tbm  |          |  tcm  |           |  tdm  |
|(客戶) |          |(供應商)|           |(產品) |
+---+---+          +---+---+           +---+---+
    |                  |                   |
    |    +-------------+-------------------+
    |    |                                 |
    v    v                                 v
+----------+     +----------+      +----------+
|   tem    |---->|   tfm    |----->|   tgm    |
|(報價)    |     |(訂單)    |      |(採購)    |
+----------+     +----+-----+      +----+-----+
                      |                 |
           +----------+-----------------+
           |          |                 |
           v          v                 v
      +--------+ +--------+       +--------+
      |  tqm   | |  tpm   |       |  thm   |--> 發票/裝箱單
      |(催貨)  | |(追蹤)  |       |(出貨)  |
      +--------+ +--------+       +---+----+
                                      |
           +--------------------------+--------------+
           |              |           |              |
           v              v           v              v
      +--------+    +--------+  +--------+    +--------+
      |  tlm   |    |  trm   |  |  tjm   |    |  tnm   |
      |(帳款)  |    |(分析)  |  |(索賠)  |    |(歸檔)  |
      +--------+    +--------+  +--------+    +--------+
                          |
                          v
                    +--------+
                    |  tmm   |
                    |(統計)  |
                    +--------+
```

---

## 欄位參照標記法

本文件使用 `[[table.field]]` 標記法進行交叉參照:

| 標記法 | 意義 |
|----------|---------|
| `[[tfm01]]` | 參照資料表 tfm01 |
| `[[tfm01.fa01]]` | 參照資料表 tfm01 中的欄位 fa01 |
| `[[tfm01.fa01]] -> [[tgm01.ga2301]]` | 外鍵關聯 |

閱讀相關文件時，使用此標記法定位確切的欄位定義。

---

## 文件導覽

- **主要流程**: `./00-overview.md`
- **模組索引**: `./_index.yaml`
- **個別模組**: `./01-tam.md` 至 `./09-thm.md`
