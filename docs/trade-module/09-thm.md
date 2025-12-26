# THM - Shipment Module (INV/PKG)

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

## Module Overview

The THM module is the final transaction step, producing INVOICE, Packing List, and Shipping Mark documents. It automatically triggers Accounts Receivable creation.

**Flow Position:**
```
[[tfm01]] (Order) + [[tgm01]] (Purchase) --> [[thm01]] (Shipment)
                                                  |
                                                  +--> INVOICE
                                                  +--> PACKING LIST
                                                  +--> SHIPPING MARK
                                                  +--> [[tlm01]] (AR)
```

---

## Table Registry

| Table | Records | Purpose | Primary Key |
|-------|---------|---------|-------------|
| thm01 | 3,697 | Shipment/Invoice master | `ha01` |
| thm02 | 11,262 | PI items | `(hb01, hb02)` |
| thm03 | 33,602 | Packing items | `(hc01, hc02, hc18)` |
| thm04 | 25,338 | Invoice items/cost | `(hd011, hd012, ...)` |
| thm05 | 34,829 | Component cost | `(he01-he09)` |
| thm06 | - | **Shipping mark** | `(hf01, ...)` |
| thm07 | 417,961 | Item sub-description | `(hg01-hg05)` |
| thm08 | 3,395 | Extra charges | `(hh010, hh011, hh02)` |

---

## THM01 - Shipment/Invoice Master

### Field Definition

```yaml
table: thm01
name: "Shipment/Invoice Master"
records: 3697
total_fields: 141
primary_key: ha01
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `ha01` | varchar(10) | NO | **Invoice/Shipment No** | PK |
| `ha02` | char(1) | YES | Type (I=Invoice) | |
| `ha03` | varchar(8) | YES | Shipment date | |
| `ha04` | varchar(10) | YES | **Customer code** | `[[tbm01.ba01]]` |
| `ha05` | varchar(3) | YES | Department | |
| `ha19` | varchar(5) | YES | **Currency** | `[[tam08.ha01]]` |
| `ha81` | varchar(3) | NO | Shipping method | |
| `ha83-87` | varchar | NO | Shipper/Consignee info | |

### Document Types

```yaml
document_codes:
  I: "Invoice"
  T: "Invoice remark"
  5: "Packing remark"
  8: "Shipping Notice remark"
  B: "Shipping Advice remark"
```

---

## THM02 - PI Items (Invoice Lines from Order)

### Field Definition

```yaml
table: thm02
name: "Shipment PI Items"
records: 11262
total_fields: 13
primary_key: "(hb01, hb02)"
```

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| `hb01` | varchar(10) | **Invoice No** | `[[thm01.ha01]]` |
| `hb02` | varchar(10) | **Product code** | `[[tfm02.fb03]]` |
| `hb03` | varchar(2) | Unit | |
| `hb06-12` | float | Qty and price fields | |

---

## THM03 - Packing Items

### Field Definition

```yaml
table: thm03
name: "Packing Items"
records: 33602
total_fields: 38
primary_key: "(hc01, hc02, hc18)"
purpose: "PACKING LIST details"
```

| Field | Type | Description |
|-------|------|-------------|
| `hc01` | varchar(10) | **Invoice No** |
| `hc02` | varchar(10) | **Product code** |
| `hc03` | varchar(20) | Item description |
| `hc04-17` | various | Specs, dimensions |
| `hc18` | float | **Sequence** |

### Packing List Content

```yaml
packing_list_fields:
  box_number: "from sequence"
  product: "[[thm03.hc02]]"
  description: "[[thm03.hc03]]"
  quantity: "per box"
  net_weight: "kg"
  gross_weight: "kg"
  dimensions: "L x W x H"
  cbm: "calculated"
```

---

## THM04 - Invoice Items/Cost Analysis

### Field Definition

```yaml
table: thm04
name: "Invoice Items"
records: 25338
total_fields: 22
primary_key: "(hd011, hd012, hd032, hd033, hd034, hd02, hd03)"
purpose: "Invoice line items with cost breakdown"
```

| Field | Type | Description |
|-------|------|-------------|
| `hd011` | varchar(10) | Invoice No |
| `hd012` | varchar(10) | Product code |
| `hd02-03` | varchar | Cost category |
| `hd11-17` | float | Cost values (material, labor, expense) |

---

## THM05 - Component Cost

### Field Definition

```yaml
table: thm05
name: "Component Cost"
records: 34829
total_fields: 11
primary_key: "(he01-he09)"
purpose: "BOM component cost tracking"
```

Links invoice items to their BOM components for cost analysis.

---

## THM06 - Shipping Mark

### Field Definition

```yaml
table: thm06
name: "Shipping Mark"
total_fields: 7
purpose: "Shipping mark template and content"
```

| Field | Description |
|-------|-------------|
| `hf01-03` | Invoice + identifier |
| `hf04` | Mark type |
| `hf05-07` | Mark content lines |

### Shipping Mark Auto-Fill

```yaml
auto_fill_fields:
  - "P/O NO." -> Customer PO from [[tfm01.fa08]]
  - "C/NO" -> Carton number (sequence)
  - "Customer PO" -> [[tfm01.fa08]]
  - "MADE IN" -> "TAIWAN" or config
```

---

## THM07 - Item Sub-Description

### Field Definition

```yaml
table: thm07
name: "Item Sub-Description"
records: 417961
total_fields: 7
primary_key: "(hg01, hg02, hg03, hg04, hg05)"
purpose: "Detailed item descriptions for invoice"
```

Largest THM table - stores multi-line product descriptions.

---

## THM08 - Extra Charges

### Field Definition

```yaml
table: thm08
name: "Extra Charges"
records: 3395
total_fields: 5
primary_key: "(hh010, hh011, hh02)"
purpose: "Freight, insurance, other charges"
```

| Field | Description |
|-------|-------------|
| `hh010` | Type (I=Invoice) |
| `hh011` | Invoice No |
| `hh02` | Sequence |
| `hh03` | Charge description |
| `hh04` | Amount |

---

## Document Generation

### INVOICE Structure

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

### PACKING LIST Structure

```yaml
packing_list_composition:
  header: "[[thm01]]"
    - invoice_no: "ha01"
    - vessel: "from schedule"
    - destination: "from order"

  items: "[[thm03]]"
    - box_no: "sequence"
    - product: "hc02"
    - description: "hc03"
    - qty_per_box: "hc##"
    - n.w.: "net weight"
    - g.w.: "gross weight"
    - dimensions: "L x W x H"
    - cbm: "calculated"

  totals:
    - total_boxes
    - total_n.w.
    - total_g.w.
    - total_cbm
```

### SHIPPING MARK Structure

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

## Auto AR Generation

### Trigger

```yaml
trigger:
  event: "[[thm01]] save (confirmed)"
  condition: "ha02 = 'I' (Invoice type)"

action:
  target: "[[tlm01]]"
  mapping:
    - "tlm01.invoice_no = [[thm01.ha01]]"
    - "tlm01.customer = [[thm01.ha04]]"
    - "tlm01.amount = calculated_total"
    - "tlm01.currency = [[thm01.ha19]]"
    - "tlm01.doc_type = 'I'"
```

### AR Calculation

```sql
AR_Amount = SUM([[thm04.line_amount]])
          + SUM([[thm08.charges]])
          - Discount
```

---

## Cross-Module Integration

### Upstream (Receiving Data)

```yaml
from_tfm:
  source: "[[tfm01]], [[tfm02]], [[tfm03]]"
  data_flow:
    - "[[tfm01.fa04]] -> [[thm01.ha04]] (customer)"
    - "[[tfm02.fb03]] -> [[thm02.hb02]] (products)"
    - "[[tfm03]] -> shipment schedule reference"

from_tgm:
  source: "[[tgm01]], [[tgm02]]"
  usage: "Reference when shipping from supplier"

from_tdm:
  source: "[[tdm08]]"
  provides: "Default packaging specs for [[thm03]]"

from_tqm:
  source: "[[tqm26]]"
  provides: "Size/color details"
  source: "[[tqm19]]/[[tqm20]]"
  provides: "Customer-specific mark templates"
```

### Downstream (Sending Data)

```yaml
to_tlm:
  trigger: "Invoice confirmation"
  action: "Create AR record"
  target: "[[tlm01]]"

to_trm:
  trigger: "Shipment completion"
  action: "Update shipment analysis"
  target: "[[trm01]], [[trm02]]"

to_tjm:
  trigger: "Quality issue reported"
  action: "Create claim record"
  target: "[[tjm01]]"

to_tmm:
  trigger: "Period-end statistics"
  action: "Aggregate to statistics tables"
  target: "[[tmm05]], [[tmm06]], [[tmm24]], [[tmm25]]"
```

---

## Common Queries

### Query Invoice with Details

```sql
SELECT
    h1.ha01 AS [Invoice],
    h1.ha03 AS [Date],
    h1.ha04 AS [Customer],
    h2.hb02 AS [Product],
    h2.hb06 AS [Qty],
    h4.hd11 AS [Amount]
FROM [[thm01]] h1
INNER JOIN [[thm02]] h2 ON h2.hb01 = h1.ha01
LEFT JOIN [[thm04]] h4 ON h4.hd011 = h1.ha01 AND h4.hd012 = h2.hb02
WHERE h1.ha01 = @InvoiceNo
```

### Query Packing List

```sql
SELECT
    h1.ha01 AS [Invoice],
    h3.hc18 AS [Box_No],
    h3.hc02 AS [Product],
    h3.hc03 AS [Description],
    h3.net_weight,
    h3.gross_weight,
    h3.cbm
FROM [[thm01]] h1
INNER JOIN [[thm03]] h3 ON h3.hc01 = h1.ha01
WHERE h1.ha01 = @InvoiceNo
ORDER BY h3.hc18
```

### Trace Invoice to Order

```sql
SELECT
    h1.ha01 AS [Invoice],
    h1.ha04 AS [Customer],
    t1.fa01 AS [PI],
    t1.fa03 AS [Order_Date],
    h1.ha03 AS [Ship_Date]
FROM [[thm01]] h1
INNER JOIN [[tfm01]] t1 ON t1.fa04 = h1.ha04
WHERE h1.ha01 = @InvoiceNo
```

---

## Navigation

- **Previous**: `./08-tgm.md` (Purchase)
- **Next**: Return to `./00-overview.md`
- **Auxiliary**: `./_auxiliary.md` (for tlm, trm, tjm)
- **Index**: `./_index.yaml`
