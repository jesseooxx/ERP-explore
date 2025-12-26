# TGM - Purchase Order Module (PO)

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

## Module Overview

The TGM module handles Purchase Orders (PO) generated from Sales Orders (PI). Each PO is linked back to its source PI via `ga2301` and `gb2601` fields.

**Flow Position:**
```
[[tfm01]] (Order) + [[tem05]] (BOM) --> [[tgm01]] (Purchase) --> [[thm01]] (Shipment)
                                                            --> [[tlm09]] (AP)
```

---

## Table Registry

| Table | Records | Purpose | Primary Key |
|-------|---------|---------|-------------|
| tgm01 | 9,139 | Purchase master | `ga01` |
| tgm02 | 28,204 | Purchase detail | `(gb01, gb02)` |
| tgm03 | 31,535 | Purchase batch/schedule | `(gc01, gc02, gc03, gc04, ...)` |
| tgm04 | 12,415 | Purchase summary | `(gd01, gd02, gd03)` |
| tgm05-09 | 0-4 | Auxiliary (mostly unused) | varies |

---

## TGM01 - Purchase Master

### Field Definition

```yaml
table: tgm01
name: "Purchase Order Master"
records: 9139
total_fields: 99
primary_key: ga01
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `ga01` | varchar(10) | NO | **PO Number** | PK |
| `ga02` | char(1) | YES | Type (F/I/S) | |
| `ga03` | varchar(8) | YES | PO date (YYYYMMDD) | |
| `ga04` | varchar(10) | YES | **Supplier code** | `[[tcm01.ca01]]` |
| `ga05` | varchar(3) | YES | Sales rep | |
| `ga06` | varchar(5) | YES | **Currency** | `[[tam08.ha01]]` |
| `ga07` | varchar(30) | YES | Supplier name | |
| `ga09` | int | YES | Item count | |
| `ga12` | varchar(20) | YES | Port of loading | |
| `ga13` | varchar(10) | YES | Customer code | `[[tbm01.ba01]]` |
| `ga15` | varchar(20) | YES | Destination | |
| `ga17` | varchar(6) | YES | Trade terms | |
| `ga2301` | varchar(10) | YES | **Link to PI** | `[[tfm01.fa01]]` |
| `ga37` | float | YES | Total amount | |
| `ga59` | varchar(8) | NO | Last update date | |

### Critical Link Field

```yaml
field: ga2301
purpose: "Links PO back to source PI"
relationship: "[[tgm01.ga2301]] -> [[tfm01.fa01]]"
usage: "Trace purchase back to customer order"
```

---

## TGM02 - Purchase Detail

### Field Definition

```yaml
table: tgm02
name: "Purchase Order Detail"
records: 28204
total_fields: 59
primary_key: "(gb01, gb02)"
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `gb01` | varchar(10) | NO | **PO Number** | `[[tgm01.ga01]]` |
| `gb02` | float | NO | **Line sequence** | PK part |
| `gb03` | varchar(20) | YES | **Product code** | `[[tdm01.da01]]` |
| `gb04` | varchar(20) | YES | Component code | |
| `gb07` | varchar(30) | YES | Product name 1 | |
| `gb08` | varchar(30) | YES | Product name 2 | |
| `gb09` | float | YES | **Purchase qty** | Calculated |
| `gb10` | varchar(6) | YES | Unit | |
| `gb11` | float | YES | Unit price | |
| `gb12` | float | YES | Line subtotal | |
| `gb131` | char(1) | YES | Main part flag (Y/N) | |
| `gb19` | float | YES | Extended price | |
| `gb20` | float | YES | Line total | |
| `gb2601` | varchar(10) | YES | **Link to PI** | `[[tfm01.fa01]]` |

### Critical Link Field

```yaml
field: gb2601
purpose: "Links PO line back to source PI"
relationship: "[[tgm02.gb2601]] -> [[tfm01.fa01]]"
usage: "Trace each purchase item to order"
```

---

## TGM03 - Purchase Batch/Schedule

### Field Definition

```yaml
table: tgm03
name: "Purchase Batch Schedule"
records: 31535
total_fields: 26
primary_key: "(gc01, gc02, gc03, gc04, gc201, gc202, gc203)"
```

| Field | Type | Description |
|-------|------|-------------|
| `gc01` | varchar(10) | **PO Number** |
| `gc02` | varchar(8) | ETD date |
| `gc03` | varchar(20) | Destination |
| `gc04` | varchar(20) | Product code |
| `gc05` | float | Batch quantity |
| `gc06` | float | Shipped quantity |
| `gc08` | char(1) | Completion (Y/N) |
| `gc09` | varchar(8) | ETA date |
| `gc10` | varchar(10) | Supplier code |

---

## TGM04 - Purchase Summary

### Field Definition

```yaml
table: tgm04
name: "Purchase Summary"
records: 12415
total_fields: 10
primary_key: "(gd01, gd02, gd03)"
```

| Field | Type | Description |
|-------|------|-------------|
| `gd01` | varchar(10) | **PO Number** |
| `gd02` | varchar(8) | ETD date |
| `gd03` | varchar(20) | Destination |
| `gd06` | float | Total CBM |
| `gd07` | float | Total net weight |
| `gd08` | float | Total gross weight |

---

## Purchase Generation Logic

### From Order to Purchase

```yaml
trigger: "Order-to-Purchase conversion"
inputs:
  - "[[tfm02]]": Order line items
  - "[[tem05]]": Order-specific BOM

process:
  1. Read [[tfm02]] for order items
  2. For each item, lookup BOM in [[tem05]]
  3. Calculate purchase qty per component
  4. Group by supplier ([[tem05.ee06]])
  5. Create [[tgm01]] per supplier
  6. Create [[tgm02]] with calculated quantities
  7. Record link in [[tfm05]]
```

### Quantity Calculation

```sql
-- Purchase quantity calculation
Purchase_Qty = Order_Qty * (BOM_Ratio_Num / BOM_Ratio_Denom)

-- SQL implementation
SELECT
    ee06 AS [Supplier],
    ee03 AS [Component],
    SUM(CAST(([[tfm02.fb09]] * ee04 / ee05) AS DECIMAL(10,2))) AS [Purchase_Qty]
FROM [[tfm02]]
INNER JOIN [[tem05]] ON ee011 = fb01 AND ee02 = fb03
WHERE fb01 = @OrderNo
GROUP BY ee06, ee03
ORDER BY ee06
```

### PO Number Format

```yaml
pattern: "{PI}-{seq}"
example: "00048-01"
explanation:
  - "00048" = Source PI number [[tfm01.fa01]]
  - "01" = Sequence number (for multiple suppliers)
```

---

## Cross-Module Integration

### Upstream (Receiving Data)

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
    - ratio: "[[tem05.ee04]]/[[tem05.ee05]] -> quantity calculation"

from_tcm:
  source: "[[tcm01]]"
  lookup_key: "[[tgm01.ga04]]"
  provides: ["supplier name", "address", "contacts"]
```

### Downstream (Sending Data)

```yaml
to_thm:
  trigger: "Shipment creation from PO"
  data_flow:
    - "[[tgm01]] -> shipment reference"
    - "[[tgm02]] -> shipment items (when direct ship)"

to_tlm:
  trigger: "PO confirmation/receipt"
  action: "Auto-create AP in [[tlm09]]"
  data:
    - "[[tgm01.ga01]] -> AP reference"
    - "[[tgm01.ga04]] -> supplier"
    - "SUM([[tgm02.gb20]]) -> AP amount"
```

---

## Traceability Queries

### Trace PO to Source Order

```sql
-- Find source PI for a PO
SELECT
    p.ga01 AS [PO],
    p.ga2301 AS [Source_PI],
    o.fa04 AS [Customer],
    o.fa03 AS [Order_Date],
    p.ga04 AS [Supplier],
    p.ga03 AS [PO_Date]
FROM [[tgm01]] p
INNER JOIN [[tfm01]] o ON o.fa01 = p.ga2301
WHERE p.ga01 = @PONumber
```

### Trace Order to All POs

```sql
-- Find all POs generated from a PI
SELECT
    o.fa01 AS [PI],
    p.ga01 AS [PO],
    p.ga04 AS [Supplier],
    SUM(pd.gb09) AS [Total_Qty],
    SUM(pd.gb20) AS [Total_Amount]
FROM [[tfm01]] o
INNER JOIN [[tgm01]] p ON p.ga2301 = o.fa01
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01
WHERE o.fa01 = @OrderNo
GROUP BY o.fa01, p.ga01, p.ga04
```

### Full Chain Query

```sql
-- Complete order->purchase->component trace
SELECT
    o.fa01 AS [Order],
    od.fb03 AS [Order_Product],
    od.fb09 AS [Order_Qty],
    b.ee03 AS [Component],
    b.ee06 AS [Supplier],
    CAST((od.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [Required_Qty],
    p.ga01 AS [PO],
    pd.gb09 AS [Purchase_Qty]
FROM [[tfm01]] o
INNER JOIN [[tfm02]] od ON od.fb01 = o.fa01
LEFT JOIN [[tem05]] b ON b.ee011 = o.fa01 AND b.ee02 = od.fb03
LEFT JOIN [[tgm01]] p ON p.ga2301 = o.fa01 AND p.ga04 = b.ee06
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01 AND pd.gb04 = b.ee03
WHERE o.fa01 = @OrderNo
ORDER BY od.fb02, b.ee07
```

---

## Navigation

- **Previous**: `./07-tfm.md` (Sales Order)
- **Next**: `./09-thm.md` (Shipment)
- **Index**: `./_index.yaml`
- **Overview**: `./00-overview.md`
