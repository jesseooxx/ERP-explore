# DataWin ERP Trade Module - Complete Business Flow

```yaml
---
id: t-module-overview
version: "1.0"
updated: "2025-12-26"
type: overview
index: "./_index.yaml"
auxiliary: "./_auxiliary.md"
---
```

## Document Purpose

This document describes the complete export trade business flow from customer setup to shipment completion. It serves as the primary reference for understanding how data flows through the T-Module system.

**Reading Order for AI Agents:**
1. This document (business flow understanding)
2. `_index.yaml` (field mappings and relationships)
3. Individual module docs (field-level details)
4. `_auxiliary.md` (support systems)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONFIGURATION LAYER                                  │
│  ┌─────────────┐  ┌─────────────┐                                           │
│  │    tam      │  │    tsm      │                                           │
│  │  (系統設定)  │  │  (運作參數)  │                                           │
│  │  26 tables  │  │  15 tables  │                                           │
│  └──────┬──────┘  └──────┬──────┘                                           │
│         │                │                                                   │
│         └────────┬───────┘                                                   │
│                  ▼                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                          MASTER DATA LAYER                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                          │
│  │    tbm      │  │    tcm      │  │    tdm      │                          │
│  │   (客戶)    │  │   (供應商)   │  │   (產品)    │                          │
│  │  23 tables  │  │  15 tables  │  │  26 tables  │                          │
│  │  PK: ba01   │  │  PK: ca01   │  │  PK: da01   │                          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                          │
│         │                │                │                                  │
│         └────────────────┼────────────────┘                                  │
│                          ▼                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         TRANSACTION LAYER                                    │
│                                                                              │
│  ┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐            │
│  │   tem   │      │   tfm   │ ───▶ │   tgm   │ ───▶ │   thm   │            │
│  │  (報價)  │      │  (訂單)  │      │  (採購)  │      │  (出貨)  │            │
│  │ 未使用   │      │ 12 tbls │      │  9 tbls │      │ 14 tbls │            │
│  │ tem05用  │      │ PK:fa01 │      │ PK:ga01 │      │ PK:ha01 │            │
│  └────┬────┘      └────┬────┘      └────┬────┘      └────┬────┘            │
│       │ BOM            │                │                │                  │
│       └───────────────▶│                │                │                  │
│                        │                │                │                  │
│                        │                │                ▼                  │
│                        │                │         ┌────────────┐            │
│                        │                │         │ INVOICE    │            │
│                        │                │         │ PACKING    │            │
│                        │                │         │ MARK       │            │
│                        │                │         └────────────┘            │
│                        │                │                                   │
├────────────────────────┼────────────────┼───────────────────────────────────┤
│                        ▼                ▼           AUXILIARY               │
│              ┌──────────────────────────────────────────────┐               │
│              │  tlm(帳款) tqm(規格) tmm(統計) trm(分析)      │               │
│              │  tjm(索賠) tpm(拋轉) tnm(歷史)               │               │
│              │  --> See _auxiliary.md                       │               │
│              └──────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Business Flow Steps

### Step 1: Master Data Setup

Before any transaction, master data must exist:

| Module | Table | Primary Key | Purpose |
|--------|-------|-------------|---------|
| tbm | `[[tbm01]]` | `[[tbm01.ba01]]` | Customer info |
| tcm | `[[tcm01]]` | `[[tcm01.ca01]]` | Supplier info |
| tdm | `[[tdm01]]` | `[[tdm01.da01]]` | Product info |
| tdm | `[[tdm05]]` | `(de01, de02)` | Standard BOM |

**BOM Structure:**
```
[[tdm05]] Standard BOM:
  de01 = Product ID (FK -> [[tdm01.da01]])
  de02 = Component ID
  de03 = Ratio numerator
  de04 = Ratio denominator
  de05 = Supplier (FK -> [[tcm01.ca01]])

Component Qty = Order Qty * (de03 / de04)
```

---

### Step 2: Quotation (tem) - NOT USED

> **PRACTICAL NOTE**: tem01/tem02 報價功能未使用。實際業務直接從 tfm 開始。
> 但 `[[tem05]]` (Order BOM) 仍被使用，儲存訂單專屬 BOM。

**Tables:** `[[tem01]]` (master - 未使用), `[[tem02]]` (detail - 未使用), `[[tem05]]` (BOM - **使用中**)

```
實際流程跳過此步驟，直接進入 Step 3 (tfm)
tem05 Order BOM 在建立訂單時自動從 tdm05 複製
```

---

### Step 3: Sales Order / PI (tfm) - ACTUAL STARTING POINT

**Tables:** `[[tfm01]]` (master), `[[tfm02]]` (detail), `[[tem05]]` (order BOM)

```
Input:
  - From quotation: [[tem01.ea01]] (optional)
  - Or direct entry with customer/products

Process:
  1. Create [[tfm01]] with fa01 (PI number)
  2. Copy/create items in [[tfm02]]
  3. TRIGGER: Copy BOM from [[tdm05]] to [[tem05]] with ee011 = [[tfm01.fa01]]

Output:
  - [[tfm01.fa01]] = Sales Contract Number
  - [[tfm02]] = Order line items
  - [[tem05]] = Order-specific BOM (ee011 = PI number)
```

**Key Field Mappings:**
| tfm Field | Source | Description |
|-----------|--------|-------------|
| `[[tfm01.fa01]]` | Auto-gen | PI Order number |
| `[[tfm01.fa03]]` | System | Order date (YYYYMMDD) |
| `[[tfm01.fa04]]` | `[[tbm01.ba01]]` | Customer code |
| `[[tfm01.fa11]]` | `[[tam17]]` | Port of loading |
| `[[tfm01.fa14]]` | `[[tam17]]` | Port of destination |
| `[[tfm01.fa19]]` | `[[tam08]]` | Currency |
| `[[tfm01.fa20]]` | `[[tam08]]`/input | Exchange rate |
| `[[tfm02.fb01]]` | `[[tfm01.fa01]]` | FK to order master |
| `[[tfm02.fb02]]` | Auto-seq | Line item sequence |
| `[[tfm02.fb03]]` | `[[tdm01.da01]]` | Product code |
| `[[tfm02.fb09]]` | User input | Order quantity |
| `[[tfm02.fb11]]` | Quotation/input | Unit price |

**Order BOM in tem05:**
```
When [[tfm02]] is created:
  INSERT INTO [[tem05]]
  SELECT 'S', [[tfm01.fa01]], de01, de02, de03, de04, de05, ...
  FROM [[tdm05]]
  WHERE de01 = [[tfm02.fb03]]
```

---

### Step 4: Shipment Scheduling (tfm03/04)

**Tables:** `[[tfm03]]` (schedule detail), `[[tfm04]]` (schedule summary)

```
Input:
  - Order: [[tfm01.fa01]]
  - Items: [[tfm02]]

Process:
  1. User assigns shipment dates and quantities per item
  2. System creates [[tfm03]] records (by product, ETD, destination)
  3. System aggregates to [[tfm04]] (by ETD, destination)

Output:
  - [[tfm03]] = Per-product shipment schedule
  - [[tfm04]] = Consolidated shipment summary
```

**Key Field Mappings:**
| Field | Description |
|-------|-------------|
| `[[tfm03.fc01]]` | PI number (FK -> [[tfm01.fa01]]) |
| `[[tfm03.fc02]]` | ETD date (YYYYMMDD) |
| `[[tfm03.fc031]]` | Destination port |
| `[[tfm03.fc04]]` | Product code (FK -> [[tfm02.fb03]]) |
| `[[tfm03.fc05]]` | Scheduled quantity |
| `[[tfm03.fc06]]` | Shipped quantity |
| `[[tfm03.fc08]]` | Completion flag (Y/N) |
| `[[tfm04.fd01]]` | PI number |
| `[[tfm04.fd02]]` | ETD date |
| `[[tfm04.fd03]]` | Destination port |
| `[[tfm04.fd06]]` | Total CBM |
| `[[tfm04.fd08]]` | Total cartons |

---

### Step 5: Purchase Order Generation (tgm)

**Tables:** `[[tgm01]]` (master), `[[tgm02]]` (detail)

```
Input:
  - Order: [[tfm01.fa01]], [[tfm02]]
  - BOM: [[tem05]] (order-specific BOM)

Process:
  1. Read order items from [[tfm02]]
  2. Look up BOM components from [[tem05]]
  3. Calculate: Purchase Qty = [[tfm02.fb09]] * ([[tem05.ee04]] / [[tem05.ee05]])
  4. Group by supplier ([[tem05.ee06]])
  5. Create [[tgm01]] per supplier
  6. Create [[tgm02]] with component details
  7. Link back: [[tgm01.ga2301]] = [[tfm01.fa01]]
                [[tgm02.gb2601]] = [[tfm01.fa01]]

Output:
  - [[tgm01.ga01]] = PO Number (format: {PI}-{seq}, e.g., "00048-01")
  - [[tgm02]] = Purchase line items
  - [[tfm05]] = Order-Purchase link record
```

**Key Field Mappings:**
| tgm Field | Source | Description |
|-----------|--------|-------------|
| `[[tgm01.ga01]]` | Auto-gen | PO number |
| `[[tgm01.ga03]]` | System | PO date |
| `[[tgm01.ga04]]` | `[[tem05.ee06]]` | Supplier code |
| `[[tgm01.ga2301]]` | `[[tfm01.fa01]]` | **Link to PI** |
| `[[tgm02.gb01]]` | `[[tgm01.ga01]]` | FK to PO master |
| `[[tgm02.gb02]]` | Auto-seq | Line sequence |
| `[[tgm02.gb03]]` | `[[tem05.ee02]]` | Product/component |
| `[[tgm02.gb09]]` | Calculated | Purchase quantity |
| `[[tgm02.gb2601]]` | `[[tfm01.fa01]]` | **Link to PI** |

**Purchase Quantity Calculation:**
```sql
Purchase_Qty = Order_Qty * (BOM_Ratio_Num / BOM_Ratio_Denom)
             = [[tfm02.fb09]] * ([[tem05.ee04]] / [[tem05.ee05]])
```

---

### Step 6: Shipment / INVOICE / Packing (thm)

**Tables:** `[[thm01]]` (master), `[[thm02]]` (PI items), `[[thm03]]` (packing), `[[thm04]]` (invoice items), `[[thm06]]` (mark)

```
Input:
  - Schedule: [[tfm03]], [[tfm04]]
  - Order: [[tfm01]], [[tfm02]]
  - Products: [[tdm01]], [[tdm08]] (packaging info)

Process:
  1. Create [[thm01]] with shipment/invoice header
  2. Load order items to [[thm02]] from [[tfm02]]
  3. Create packing items in [[thm03]] (from [[tdm08]] or manual)
  4. Create invoice items in [[thm04]]
  5. Setup shipping mark in [[thm06]]
  6. TRIGGER: Auto-create AR in [[tlm01]]

Output Documents:
  - INVOICE: [[thm01]] + [[thm02]] + [[thm04]]
  - PACKING LIST: [[thm01]] + [[thm03]]
  - SHIPPING MARK: [[thm06]]
```

**Key Field Mappings:**
| thm Field | Source | Description |
|-----------|--------|-------------|
| `[[thm01.ha01]]` | Auto-gen | Invoice/Shipment number |
| `[[thm01.ha03]]` | System | Shipment date |
| `[[thm01.ha04]]` | `[[tfm01.fa04]]` | Customer code |
| `[[thm01.ha19]]` | `[[tfm01.fa19]]` | Currency |
| `[[thm02.hb01]]` | `[[thm01.ha01]]` | FK to shipment |
| `[[thm02.hb02]]` | `[[tfm02.fb03]]` | Product code |
| `[[thm03]]` | Packing details | Box numbers, dimensions |
| `[[thm04]]` | Invoice line items | Qty, price, amount |
| `[[thm06]]` | Shipping mark | Mark template and content |

**Auto AR Generation:**
```
ON [[thm01]] SAVE:
  INSERT INTO [[tlm01]] (
    invoice_no = [[thm01.ha01]],
    customer = [[thm01.ha04]],
    amount = SUM([[thm04.amount]]),
    currency = [[thm01.ha19]],
    doc_type = 'I'  -- Invoice
  )
```

---

## Complete Data Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                      │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [[tbm01.ba01]] ─────────────────────────────────────────────────────┐     │
│       │                                                               │     │
│       ▼                                                               │     │
│  [[tem01.ea02]] ──▶ [[tfm01.fa04]] ──▶ [[thm01.ha04]] ──▶ [[tlm01]]  │     │
│                                                                       │     │
│  [[tdm01.da01]] ─────────────────────────────────────────────────────┤     │
│       │                                                               │     │
│       ▼                                                               │     │
│  [[tem02.eb03]] ──▶ [[tfm02.fb03]] ──▶ [[thm02.hb02]]                │     │
│       │                    │                                          │     │
│       │                    ▼                                          │     │
│       │              [[tem05.ee02]] (Order BOM)                       │     │
│       │                    │                                          │     │
│       │                    ▼                                          │     │
│       │              [[tgm02.gb03]] (Purchase)                        │     │
│       │                                                               │     │
│  [[tdm05]] ──────────────────────────────────────────────────────────┤     │
│  (Standard BOM)            │                                          │     │
│       │                    ▼                                          │     │
│       └──────────▶ [[tem05]] (Order BOM)                              │     │
│                           │                                           │     │
│                           ▼                                           │     │
│                    Purchase Qty Calculation                           │     │
│                           │                                           │     │
│                           ▼                                           │     │
│                    [[tgm02.gb09]]                                     │     │
│                                                                       │     │
│  [[tfm01.fa01]] ─────────────────────────────────────────────────────┤     │
│       │                                                               │     │
│       ├──▶ [[tfm02.fb01]]                                            │     │
│       ├──▶ [[tfm03.fc01]]                                            │     │
│       ├──▶ [[tfm04.fd01]]                                            │     │
│       ├──▶ [[tfm05.fe01]]                                            │     │
│       ├──▶ [[tgm01.ga2301]] ◀── Link to PI                           │     │
│       ├──▶ [[tgm02.gb2601]] ◀── Link to PI                           │     │
│       └──▶ [[tem05.ee011]] ◀── Order BOM identifier                  │     │
│                                                                       │     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Formulas

### BOM Component Calculation
```
Component_Qty = Order_Qty * (Ratio_Num / Ratio_Denom)

Standard BOM: [[tdm05.de03]] / [[tdm05.de04]]
Order BOM:    [[tem05.ee04]] / [[tem05.ee05]]
```

### CBM Calculation
```
Total_CBM = Ship_Qty * (Outer_CBM / Outer_Qty)
          = [[tfm03.fc05]] * ([[tfm02.fb25]] / [[tfm02.fb23]])
```

### Invoice Amount
```
Line_Amount = Qty * Unit_Price
            = [[thm04.qty]] * [[thm04.unit_price]]

Total = SUM(Line_Amount) + Freight + Insurance - Discount
```

---

## Module Quick Reference

| Module | Tables | Primary Key | Main Purpose | Next Step |
|--------|--------|-------------|--------------|-----------|
| tam | 26 | varies | System config | - |
| tsm | 15 | varies | Runtime params | - |
| tbm | 23 | `[[tbm01.ba01]]` | Customer | tem/tfm |
| tcm | 15 | `[[tcm01.ca01]]` | Supplier | tgm |
| tdm | 26 | `[[tdm01.da01]]` | Product/BOM | tem/tfm |
| tem | 17 | `[[tem01.ea01]]` | Quotation (未使用, tem05除外) | tfm |
| tfm | 12 | `[[tfm01.fa01]]` | Sales Order | tgm/thm |
| tgm | 9 | `[[tgm01.ga01]]` | Purchase | thm |
| thm | 14 | `[[thm01.ha01]]` | Shipment/INV/PKG | tlm |

---

## Navigation

- **Index**: `./_index.yaml` - Field mappings and module registry
- **Auxiliary**: `./_auxiliary.md` - Support modules (tlm, tqm, tmm, etc.)
- **Module Details**: `./01-tam.md` through `./09-thm.md`
