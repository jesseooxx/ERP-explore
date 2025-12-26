# TFM - Sales Order Module (PI)

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

## Module Overview

The TFM module handles Sales Orders (PI - Proforma Invoice) which is the core transaction document linking customer requirements to procurement and shipment.

**Flow Position:**
```
[[tem01]] (Quotation) --> [[tfm01]] (Order) --> [[tgm01]] (Purchase)
                                           --> [[thm01]] (Shipment)
```

---

## Table Registry

| Table | Records | Purpose | Primary Key |
|-------|---------|---------|-------------|
| tfm01 | 5,293 | Order master | `fa01` |
| tfm02 | 20,488 | Order detail | `(fb01, fb02)` |
| tfm03 | 23,446 | Shipment schedule detail | `(fc01, fc02, fc031..., fc04)` |
| tfm04 | 8,306 | Shipment schedule summary | `(fd01, fd02, fd03)` |
| tfm05 | 27,582 | Order-Purchase link | `(fe01, fe03, fe04, fe07, fe25)` |
| tfm09-12 | 0 | Customs declaration (unused) | varies |

---

## TFM01 - Order Master

### Field Definition

```yaml
table: tfm01
name: "Sales Order Master"
records: 5293
total_fields: 99
primary_key: fa01
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `fa01` | varchar(10) | NO | **PI Order Number** | PK |
| `fa02` | char(1) | YES | Order type (I=Import/Export) | |
| `fa03` | varchar(8) | YES | Order date (YYYYMMDD) | |
| `fa04` | varchar(10) | YES | **Customer code** | `[[tbm01.ba01]]` |
| `fa05` | varchar(3) | YES | Sales rep code | |
| `fa07` | varchar(30) | YES | Contact person | |
| `fa08` | varchar(20) | YES | Customer PO number | |
| `fa09` | char(1) | YES | Status | |
| `fa11` | varchar(20) | YES | Port of loading | `[[tam17]]` |
| `fa14` | varchar(20) | YES | Port of destination | `[[tam17]]` |
| `fa17` | varchar(6) | YES | Trade terms (FOB/CIF) | `[[tam13]]` |
| `fa19` | varchar(5) | YES | **Currency** | `[[tam08.ha01]]` |
| `fa20` | float | YES | Exchange rate | |
| `fa32` | varchar(8) | YES | Expected shipment date | |
| `fa37` | float | YES | Total amount | |
| `fa63` | char(1) | YES | **Completion flag** (Y/N) | |
| `fa64` | char(1) | YES | Cancel flag (Y/N) | |

### Key Relationships

```yaml
outbound_references:
  - field: "fa04"
    target: "[[tbm01.ba01]]"
    description: "Customer master"
  - field: "fa19"
    target: "[[tam08.ha01]]"
    description: "Currency code"

inbound_references:
  - source: "[[tfm02.fb01]]"
    description: "Order detail lines"
  - source: "[[tfm03.fc01]]"
    description: "Shipment schedules"
  - source: "[[tgm01.ga2301]]"
    description: "Purchase orders generated"
  - source: "[[tem05.ee011]]"
    description: "Order-specific BOM"
```

---

## TFM02 - Order Detail

### Field Definition

```yaml
table: tfm02
name: "Sales Order Detail"
records: 20488
total_fields: 67
primary_key: "(fb01, fb02)"
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `fb01` | varchar(10) | NO | **PI Number** | `[[tfm01.fa01]]` |
| `fb02` | float | NO | **Line sequence** | PK part |
| `fb03` | varchar(20) | YES | **Product code** | `[[tdm01.da01]]` |
| `fb06` | varchar(30) | YES | Product name line 1 | |
| `fb07` | varchar(30) | YES | Product name line 2 | |
| `fb09` | float | YES | **Order quantity** | |
| `fb10` | varchar(6) | YES | Unit | |
| `fb11` | float | YES | Unit price | |
| `fb12` | float | YES | Line amount | |
| `fb13` | varchar(10) | YES | Supplier code | `[[tcm01.ca01]]` |
| `fb22` | float | YES | Inner pack qty | |
| `fb23` | float | YES | **Outer carton qty** | For CBM calc |
| `fb25` | float | YES | **CBM per carton** | For CBM calc |
| `fb53` | char(1) | YES | Completion flag | |

### BOM Copy Trigger

```sql
-- When tfm02 is inserted, copy standard BOM to order BOM
ON INSERT tfm02:
  INSERT INTO [[tem05]] (ee010, ee011, ee02, ee03, ee04, ee05, ee06, ee07, ee08, ee10)
  SELECT 'S', NEW.fb01, de01, de02, de03, de04, de05, de06, de07, de09
  FROM [[tdm05]]
  WHERE de01 = NEW.fb03 AND de18 = 'Y'
```

---

## TFM03 - Shipment Schedule Detail

### Field Definition

```yaml
table: tfm03
name: "Shipment Schedule Detail"
records: 23446
total_fields: 15
primary_key: "(fc01, fc02, fc031, fc032, fc033, fc034, fc04)"
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `fc01` | varchar(10) | NO | **PI Number** | `[[tfm01.fa01]]` |
| `fc02` | varchar(8) | NO | **ETD date** (YYYYMMDD) | PK part |
| `fc031` | varchar(20) | NO | **Destination port** | PK part |
| `fc032-034` | varchar | NO | (Reserved) | PK parts |
| `fc04` | varchar(20) | NO | **Product code** | `[[tfm02.fb03]]` |
| `fc05` | float | YES | **Scheduled qty** | |
| `fc06` | float | YES | **Shipped qty** | |
| `fc08` | char(1) | YES | **Completion** (Y/N) | |
| `fc09` | varchar(8) | YES | Original ETD | |
| `fc10` | varchar(10) | YES | Customer code | |

### Schedule Logic

```yaml
constraints:
  - "SUM(fc05) by product <= [[tfm02.fb09]]"
  - "fc06 <= fc05"
  - "fc08 = 'Y' when fc06 >= fc05"

aggregation:
  - target: "[[tfm04]]"
    group_by: ["fc01", "fc02", "fc031"]
    sum_fields: ["fc05"]
```

---

## TFM04 - Shipment Schedule Summary

### Field Definition

```yaml
table: tfm04
name: "Shipment Schedule Summary"
records: 8306
total_fields: 10
primary_key: "(fd01, fd02, fd03)"
```

| Field | Type | Null | Description |
|-------|------|------|-------------|
| `fd01` | varchar(10) | NO | **PI Number** |
| `fd02` | varchar(8) | NO | **ETD date** |
| `fd03` | varchar(20) | NO | **Destination** |
| `fd04` | varchar(30) | YES | Vessel/Voyage |
| `fd06` | float | YES | **Total CBM** |
| `fd07` | float | YES | Total net weight |
| `fd08` | float | YES | **Total cartons** |

### Calculation

```sql
-- CBM calculation
fd06 = SUM(fc05 * ([[tfm02.fb25]] / [[tfm02.fb23]]))
     WHERE tfm02.fb01 = fc01 AND tfm02.fb03 = fc04
```

---

## TFM05 - Order-Purchase Link

### Field Definition

```yaml
table: tfm05
name: "Order-Purchase Selection"
records: 27582
total_fields: 30
primary_key: "(fe01, fe03, fe04, fe07, fe25)"
```

| Field | Type | Null | Description | Reference |
|-------|------|------|-------------|-----------|
| `fe01` | varchar(10) | NO | **PI Number** | `[[tfm01.fa01]]` |
| `fe02` | float | YES | Line sequence | |
| `fe03` | varchar(20) | NO | **Product code** | `[[tfm02.fb03]]` |
| `fe04` | varchar(10) | NO | **Supplier code** | `[[tcm01.ca01]]` |
| `fe06` | float | YES | **Order qty** | |
| `fe07` | varchar(5) | NO | **Currency** | |
| `fe08` | float | YES | Unit price | |
| `fe12` | varchar(10) | YES | **PO Number** | `[[tgm01.ga01]]` |

### Purpose

Records the supplier selection for each order item, used during purchase order generation.

---

## Cross-Module Integration

### Upstream (Receiving Data)

```yaml
from_tem:
  trigger: "Quotation confirmation"
  data_flow:
    - "[[tem01]] -> [[tfm01]]"
    - "[[tem02]] -> [[tfm02]]"
    - "[[tem05]] preserved with ee011 updated"

from_tbm:
  field: "[[tfm01.fa04]]"
  source: "[[tbm01.ba01]]"
  brings: ["customer name", "address", "contacts"]

from_tdm:
  field: "[[tfm02.fb03]]"
  source: "[[tdm01.da01]]"
  brings: ["product name", "specs", "packaging"]
  triggers: "BOM copy to [[tem05]]"
```

### Downstream (Sending Data)

```yaml
to_tgm:
  trigger: "Order-to-Purchase conversion"
  link_fields:
    - "[[tgm01.ga2301]] = [[tfm01.fa01]]"
    - "[[tgm02.gb2601]] = [[tfm01.fa01]]"
  calculation: "Purchase qty from BOM ratio"

to_thm:
  trigger: "Shipment creation"
  data_flow:
    - "[[tfm01.fa04]] -> [[thm01.ha04]]"
    - "[[tfm02]] -> [[thm02]]"
    - "[[tfm03]] -> shipment schedule reference"

to_tem05:
  trigger: "On [[tfm02]] insert"
  action: "Copy BOM from [[tdm05]]"
  key: "ee011 = [[tfm01.fa01]]"
```

---

## Common Queries

### Query Order with Details

```sql
SELECT
    t1.fa01 AS [PI],
    t1.fa04 AS [Customer],
    t1.fa03 AS [Date],
    t2.fb02 AS [Line],
    t2.fb03 AS [Product],
    t2.fb09 AS [Qty],
    t2.fb11 AS [Price],
    t2.fb12 AS [Amount]
FROM [[tfm01]] t1
INNER JOIN [[tfm02]] t2 ON t2.fb01 = t1.fa01
WHERE t1.fa01 = @OrderNo
ORDER BY t2.fb02
```

### Query Order with BOM

```sql
SELECT
    t1.fa01, t2.fb03, t2.fb09,
    b.ee03 AS [Component],
    CAST((t2.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [Component_Qty],
    b.ee06 AS [Supplier]
FROM [[tfm01]] t1
INNER JOIN [[tfm02]] t2 ON t2.fb01 = t1.fa01
LEFT JOIN [[tem05]] b ON b.ee011 = t1.fa01 AND b.ee02 = t2.fb03
WHERE t1.fa01 = @OrderNo
```

---

## Navigation

- **Previous**: `./06-tem.md` (Quotation)
- **Next**: `./08-tgm.md` (Purchase)
- **Index**: `./_index.yaml`
- **Overview**: `./00-overview.md`
