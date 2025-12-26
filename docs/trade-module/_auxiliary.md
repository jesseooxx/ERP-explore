# T Module Auxiliary Systems Reference

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

## Purpose

This document consolidates all auxiliary T-module subsystems for AI reference.
These modules support the main business flow (tem->tfm->tgm->thm) but are not
part of the core transaction path.

---

## Module Registry

```json
{
  "auxiliary_modules": {
    "financial": {
      "tlm": {"tables": 20, "purpose": "accounts_receivable_payable", "triggers_from": ["thm", "tgm"]},
      "tmm": {"tables": 30, "purpose": "statistics_reporting", "aggregates_from": ["tfm", "tgm", "thm"]}
    },
    "operational": {
      "tqm": {"tables": 26, "purpose": "specs_expediting_catalog", "supports": ["tdm", "thm"]},
      "trm": {"tables": 2, "purpose": "shipment_analysis", "analyzes": ["thm"]},
      "tjm": {"tables": 2, "purpose": "claims_disputes", "triggered_by": ["thm"]},
      "tpm": {"tables": 2, "purpose": "transfer_tracking", "tracks": ["tfm->tgm", "tgm->thm"]},
      "tnm": {"tables": 4, "purpose": "history_archive", "archives": ["tfm", "tgm", "thm"]}
    },
    "configuration": {
      "tam": {"tables": 26, "purpose": "system_settings", "scope": "global"},
      "tsm": {"tables": 15, "purpose": "runtime_parameters", "scope": "module"}
    }
  }
}
```

---

## 1. TLM - Accounts Management (20 tables)

### 1.1 Module Definition
```yaml
module_id: tlm
name_zh: "帳款管理"
name_en: "Accounts Receivable/Payable"
table_range: tlm01-tlm20
field_prefix: "l{table_seq}{field_seq}"  # e.g., la01, lb01
```

### 1.2 Table Classification
| Table | Purpose | Triggered By | Key Fields |
|-------|---------|--------------|------------|
| tlm01-08 | AR (Accounts Receivable) | `[[thm01]]` save | customer, invoice_no, amount, currency |
| tlm09-14 | AP (Accounts Payable) | `[[tgm01]]` save | supplier, po_no, amount, currency |
| tlm15-16 | L/C Settlement | manual | lc_no, bank, negotiation_amount |
| tlm17-20 | Misc/Remittance | manual | remittance_bank, transfer_date |

### 1.3 Auto-Generation Rules
```
TRIGGER: [[thm01]] INSERT/UPDATE (ha63='saved')
ACTION:  INSERT INTO tlm01 (
           invoice_no = [[thm01.ha01]],
           customer   = [[thm01.ha04]],
           amount     = SUM([[thm02.hb12]]),
           currency   = [[thm01.ha19]]
         )

TRIGGER: [[tgm01]] INSERT/UPDATE (ga63='saved')
ACTION:  INSERT INTO tlm09 (
           po_no      = [[tgm01.ga01]],
           supplier   = [[tgm01.ga04]],
           amount     = SUM([[tgm02.gb20]]),
           currency   = [[tgm01.ga06]]
         )
```

### 1.4 Cross-References
- `[[tlm01.customer]]` -> `[[tbm01.ba01]]`
- `[[tlm01.invoice_no]]` -> `[[thm01.ha01]]`
- `[[tlm09.supplier]]` -> `[[tcm01.ca01]]`
- `[[tlm09.po_no]]` -> `[[tgm01.ga01]]`

---

## 2. TQM - Specs/Expediting/Catalog (26 tables)

### 2.1 Module Definition
```yaml
module_id: tqm
name_zh: "規格/催貨/型錄"
name_en: "Specifications, Expediting, Catalog"
table_range: tqm01-tqm26
field_prefix: "q{table_seq}{field_seq}"
```

### 2.2 Functional Groups
| Group | Tables | Purpose |
|-------|--------|---------|
| Expediting | tqm01-03 | Delivery follow-up by PI and PO |
| Material Specs | tqm04-05 | Material properties and cost analysis |
| Ship Pre-assign | tqm06-07 | Shipment pre-scheduling |
| Item Category | tqm08-09 | Product categorization |
| Requisition | tqm15-17 | Shipment requisition |
| Catalog/Style | tqm19-22 | Product catalog and style definitions |
| Spec Items | tqm23-24 | Specification item details |
| Size/Color | tqm25-26 | Size and color data |

### 2.3 Packing List Related
```yaml
packing_sources:
  - table: "[[tqm26]]"
    provides: [size, color, dimensions]
    used_by: "[[thm03]]"
  - table: "[[tqm19]]/[[tqm20]]"
    provides: [customer_specific_catalog]
    used_by: "[[thm06]]"  # shipping mark
```

### 2.4 Cross-References
- `[[tqm04.material]]` -> `[[tdm01.da01]]`
- `[[tqm01.sc_no]]` -> `[[tfm01.fa01]]`
- `[[tqm03.po_no]]` -> `[[tgm01.ga01]]`

---

## 3. TMM - Statistics/Reporting (30 tables)

### 3.1 Module Definition
```yaml
module_id: tmm
name_zh: "統計報表"
name_en: "Statistics and Reporting"
table_range: tmm01-tmm26 + logs
field_prefix: "m{table_seq}{field_seq}"
```

### 3.2 Key Statistics Tables
| Table | Records | Dimensions | Purpose |
|-------|---------|------------|---------|
| tmm01 | 719,881 | user, date, operation | Operation log |
| tmm03 | 1,065,120 | product, customer, period | Sales stats |
| tmm13 | 1,111,548 | customer, period, currency | AR stats |
| tmm24 | 533,088 | customer, period | Customer sales |
| tmm25 | 610,464 | product, period | Product sales |

### 3.3 Data Sources
```yaml
aggregation_sources:
  tmm02-06: ["[[tfm01]]", "[[tfm02]]", "[[tgm01]]", "[[tgm02]]", "[[thm01]]", "[[thm02]]"]
  tmm13: ["[[tlm01]]"]
  tmm24: ["[[thm01]]", "[[thm02]]", "grouped by [[tbm01.ba01]]"]
  tmm25: ["[[thm01]]", "[[thm02]]", "grouped by [[tdm01.da01]]"]
```

---

## 4. TRM - Shipment Analysis (2 tables)

### 4.1 Module Definition
```yaml
module_id: trm
name_zh: "出貨分析"
name_en: "Shipment Analysis"
table_range: trm01-trm02
```

### 4.2 Tables
| Table | Purpose | Dimensions |
|-------|---------|------------|
| trm01 | Customer shipment analysis | customer x product x period |
| trm02 | Product shipment analysis | product x customer x period |

### 4.3 Data Source
- Aggregates from `[[thm01]]` and `[[thm02]]`

---

## 5. TJM - Claims/Disputes (2 tables)

### 5.1 Module Definition
```yaml
module_id: tjm
name_zh: "索賠管理"
name_en: "Claims and Disputes"
table_range: tjm01-tjm02
```

### 5.2 Tables
| Table | Purpose | Triggered By |
|-------|---------|--------------|
| tjm01 | Claims master | Post-shipment quality issues |
| tjm02 | Claims detail | Item-level claim records |

### 5.3 Cross-References
- `[[tjm01.invoice_no]]` -> `[[thm01.ha01]]`
- `[[tjm01.customer]]` -> `[[tbm01.ba01]]`

---

## 6. TPM - Transfer Tracking (2 tables)

### 6.1 Module Definition
```yaml
module_id: tpm
name_zh: "拋轉記錄"
name_en: "Transfer Tracking"
table_range: tpm03-tpm04
```

### 6.2 Tables
| Table | Tracks | From -> To |
|-------|--------|------------|
| tpm03 | Order to Purchase | `[[tfm01]]` -> `[[tgm01]]` |
| tpm04 | Purchase to Shipment | `[[tgm01]]` -> `[[thm01]]` |

### 6.3 Mapping Structure
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

## 7. TNM - History Archive (4 tables)

### 7.1 Module Definition
```yaml
module_id: tnm
name_zh: "歷史歸檔"
name_en: "History Archive"
table_range: tnm01-tnm04
```

### 7.2 Tables
| Table | Archives From | Trigger Condition |
|-------|---------------|-------------------|
| tnm01 | `[[tfm01]]` | Order completed (fa63='Y') |
| tnm02 | `[[tfm02]]` | Order detail archive |
| tnm03 | `[[tgm01]]` | Purchase completed |
| tnm04 | `[[tgm02]]` | Purchase detail archive |

---

## 8. TAM - System Settings (26 tables)

### 8.1 Module Definition
```yaml
module_id: tam
name_zh: "系統設定"
name_en: "System Settings"
table_range: tam01-tam26
field_prefix: "{varies}"
```

### 8.2 Key Configuration Tables
| Table | Purpose | Used By |
|-------|---------|---------|
| tam01 | Company info | All modules |
| tam05-07 | User/permissions | Login, access control |
| tam08-09 | Currency/rates | `[[tfm01.fa19]]`, `[[tgm01.ga06]]`, `[[thm01.ha19]]` |
| tam17 | Ports/countries | `[[tfm01.fa11]]`, `[[tfm01.fa14]]` |

---

## 9. TSM - Runtime Parameters (15 tables)

### 9.1 Module Definition
```yaml
module_id: tsm
name_zh: "運作參數"
name_en: "Runtime Parameters"
table_range: tsm01-tsm13
```

### 9.2 Key Parameter Tables
| Table | Purpose | Example Usage |
|-------|---------|---------------|
| tsm01 | System startup params | CBM/CUFT conversion (IC15=35.315) |
| tsm03 | Unit conversion | PCS <-> BOX <-> PALLET |
| tsm04 | Report formats | INVOICE, Packing List templates |
| tsm10 | Auto-numbering rules | Document number generation |

---

## Cross-Module Dependency Graph

```
                    ┌─────────┐
                    │   tam   │ (global config)
                    │   tsm   │ (runtime params)
                    └────┬────┘
                         │
    ┌────────────────────┼────────────────────┐
    │                    │                    │
    ▼                    ▼                    ▼
┌───────┐          ┌───────┐           ┌───────┐
│  tbm  │          │  tcm  │           │  tdm  │
│(cust) │          │(supp) │           │(prod) │
└───┬───┘          └───┬───┘           └───┬───┘
    │                  │                   │
    │    ┌─────────────┴───────────────────┤
    │    │                                 │
    ▼    ▼                                 ▼
┌──────────┐     ┌──────────┐      ┌──────────┐
│   tem    │────▶│   tfm    │─────▶│   tgm    │
│(quote)   │     │(order)   │      │(purchase)│
└──────────┘     └────┬─────┘      └────┬─────┘
                      │                 │
           ┌──────────┴─────────────────┤
           │          │                 │
           ▼          ▼                 ▼
      ┌────────┐ ┌────────┐       ┌────────┐
      │  tqm   │ │  tpm   │       │  thm   │──▶ INV/PKG
      │(exped.)│ │(track) │       │(ship)  │
      └────────┘ └────────┘       └───┬────┘
                                      │
           ┌──────────────────────────┼──────────────┐
           │              │           │              │
           ▼              ▼           ▼              ▼
      ┌────────┐    ┌────────┐  ┌────────┐    ┌────────┐
      │  tlm   │    │  trm   │  │  tjm   │    │  tnm   │
      │(A/R-P) │    │(anlys) │  │(claim) │    │(hist)  │
      └────────┘    └────────┘  └────────┘    └────────┘
                          │
                          ▼
                    ┌────────┐
                    │  tmm   │
                    │(stats) │
                    └────────┘
```

---

## Field Reference Notation

This document uses `[[table.field]]` notation for cross-references:

| Notation | Meaning |
|----------|---------|
| `[[tfm01]]` | Reference to table tfm01 |
| `[[tfm01.fa01]]` | Reference to field fa01 in table tfm01 |
| `[[tfm01.fa01]] -> [[tgm01.ga2301]]` | FK relationship |

When reading related documents, use this notation to locate exact field definitions.

---

## Document Navigation

- **Main Flow**: `./00-overview.md`
- **Module Index**: `./_index.yaml`
- **Individual Modules**: `./01-tam.md` through `./09-thm.md`
