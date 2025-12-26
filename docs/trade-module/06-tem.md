# TEM - Quotation Module

```yaml
---
module_id: tem
name_zh: "報價單"
name_en: "Quotation"
table_range: tem01-tem17
field_prefix: "e{table_char}{seq}"
layer: transaction
tables: 17
primary_key: "[[tem01.ea01]]"
flow_position: 1
receives_from: ["[[tbm01]]", "[[tdm01]]"]
sends_to: ["[[tfm01]]"]
index: "./_index.yaml"
practical_usage: "tem01/tem02 NOT USED; tem05 (Order BOM) IS USED"
---
```

## Module Overview

TEM contains the quotation functionality and order-specific BOM storage.

**PRACTICAL NOTE**:
- `tem01`/`tem02` (報價單) - **未使用**，實際業務直接從 tfm 開始
- `tem05` (Order BOM) - **有使用**，儲存訂單專屬 BOM

**Critical Role**: `[[tem05]]` stores order-specific BOM (copied from `[[tdm05]]` when order is created).

**Actual Flow (skips quotation):**
```
[[tbm01]] + [[tdm01]] --> [[tfm01]] (Order) --> [[tgm01]] (Purchase)
                               |
                               +--> [[tem05]] (Order BOM, auto-copied from [[tdm05]])
```

---

## Table Registry

| Table | Purpose | Primary Key |
|-------|---------|-------------|
| tem01 | **Quotation master** (53 fields) | `ea01` |
| tem02 | **Quotation detail** (47 fields) | `(eb01, eb02)` |
| tem03 | Quotation sub-descriptions | `(ec01, ec02, ec03)` |
| tem04 | Quotation remarks | - |
| tem05 | **Order BOM** (20 fields) | `(ee011, ee02, ee03)` |
| tem06-10 | Reserved | - |
| tem11-17 | Extended data | - |

---

## TEM01 - Quotation Master

### Field Definition

```yaml
table: tem01
name: "Quotation Master"
total_fields: 53
primary_key: ea01
```

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| `ea01` | varchar(10) | **Quotation No** (PK) | |
| `ea02` | varchar(10) | **Customer code** | `[[tbm01.ba01]]` |
| `ea03` | varchar(8) | Quotation date | YYYYMMDD |
| `ea04` | varchar(3) | Sales rep | |
| `ea05` | varchar(5) | Currency | `[[tam08.ha01]]` |
| `ea06` | varchar(50) | Customer name | |
| `ea07` | int | Item count | |
| `ea08` | float | Total amount | |
| `ea09` | char(1) | Status (N=New, C=Converted) | |
| `ea10` | varchar(10) | Converted to PI | `[[tfm01.fa01]]` |

---

## TEM02 - Quotation Detail

### Field Definition

```yaml
table: tem02
name: "Quotation Detail"
total_fields: 47
primary_key: "(eb01, eb02)"
```

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| `eb01` | varchar(10) | **Quotation No** | `[[tem01.ea01]]` |
| `eb02` | float | **Line sequence** | PK part |
| `eb03` | varchar(20) | **Product code** | `[[tdm01.da01]]` |
| `eb04` | varchar(50) | Product name | |
| `eb05` | float | Quantity | |
| `eb06` | varchar(6) | Unit | |
| `eb07` | float | Unit price | |
| `eb08` | float | Line amount | |
| `eb09` | float | Discount % | |
| `eb10` | float | Net amount | |

---

## TEM05 - Order BOM (Critical)

### Field Definition

```yaml
table: tem05
name: "Order-specific Bill of Materials"
total_fields: 20
primary_key: "(ee011, ee02, ee03)"
purpose: "Stores BOM specific to each order (copied from [[tdm05]])"
critical: true
```

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| `ee011` | varchar(10) | **Order No** | `[[tfm01.fa01]]` |
| `ee02` | varchar(20) | **Product code** | `[[tdm01.da01]]` |
| `ee03` | varchar(20) | **Component code** | `[[tdm01.da01]]` |
| `ee04` | float | **Ratio numerator** | Calculation |
| `ee05` | float | **Ratio denominator** | Calculation |
| `ee06` | varchar(10) | **Supplier code** | `[[tcm01.ca01]]` |
| `ee07` | int | BOM sequence | |
| `ee08` | float | Component price | |
| `ee09` | varchar(6) | Unit | |
| `ee10` | char(1) | Main part (Y/N) | |

### Primary Key Note

```yaml
pk_structure:
  ee011: "Order number (links to [[tfm01.fa01]])"
  ee02: "Product code being ordered"
  ee03: "Component code in BOM"
  uniqueness: "One row per component per product per order"
```

### BOM Copy Process

```yaml
trigger: "When [[tfm02]] line is created"
source: "[[tdm05]] (Standard BOM)"
target: "[[tem05]] (Order BOM)"

process:
  1. "For each [[tfm02]] line added:"
  2. "  Lookup [[tdm05]] WHERE de01 = [[tfm02.fb03]]"
  3. "  Copy each BOM row to [[tem05]]:"
  4. "    ee011 = [[tfm01.fa01]] (order no)"
  5. "    ee02 = [[tfm02.fb03]] (product)"
  6. "    ee03-ee10 copied from de03-de10"
```

---

## Purchase Calculation Formula

```yaml
formula: "Purchase_Qty = Order_Qty * (ee04 / ee05)"

example:
  order_no: "00048"
  product: "WIDGET-A"
  order_qty: 1000  # [[tfm02.fb09]]
  component: "SCREW-01"
  ee04: 4   # need 4 screws
  ee05: 1   # per 1 product
  supplier: "SUP-001"  # ee06
  result: 4000  # purchase qty for this supplier
```

### SQL Implementation

```sql
-- Generate purchase requirements from order
SELECT
    e.ee06 AS [Supplier],
    e.ee03 AS [Component],
    e.ee10 AS [MainPart],
    SUM(CAST((f.fb09 * e.ee04 / e.ee05) AS DECIMAL(10,2))) AS [Purchase_Qty],
    e.ee08 AS [Unit_Price],
    SUM(CAST((f.fb09 * e.ee04 / e.ee05) AS DECIMAL(10,2))) * e.ee08 AS [Total_Amount]
FROM [[tfm02]] f
INNER JOIN [[tem05]] e ON e.ee011 = f.fb01 AND e.ee02 = f.fb03
WHERE f.fb01 = @OrderNo
GROUP BY e.ee06, e.ee03, e.ee10, e.ee08
ORDER BY e.ee06, e.ee10 DESC, e.ee03
```

---

## Cross-Module Integration

### Upstream (Receiving Data)

```yaml
from_tbm:
  source: "[[tbm01]]"
  provides: "Customer info for quotation"
  field_map:
    - "[[tbm01.ba01]] -> [[tem01.ea02]]"

from_tdm:
  source: "[[tdm01]], [[tdm05]]"
  provides: "Product info, Standard BOM"
  trigger: "BOM copy on order creation"
```

### Downstream (Sending Data)

```yaml
to_tfm:
  trigger: "Quotation conversion"
  data_flow:
    - "[[tem01]] -> [[tfm01]] (header)"
    - "[[tem02]] -> [[tfm02]] (lines)"
  triggers: ["Copy [[tdm05]] to [[tem05]]"]

to_tgm:
  via: "[[tem05]] (Order BOM)"
  provides: "Component requirements for PO generation"
  link: "[[tem05.ee011]] = [[tfm01.fa01]] = [[tgm01.ga2301]]"
```

---

## Complete Order-to-Purchase Trace

```
[[tem01]] (Quotation)
    |
    v (convert to order)
[[tfm01]] (Order)
    |
    +---> [[tfm02]] (Order Lines)
    |         |
    |         v (trigger BOM copy)
    |     [[tem05]] (Order BOM)
    |         |
    |         +--- ee011 = fa01 (order no)
    |         +--- ee06 = supplier
    |         +--- ee04/ee05 = ratio
    |
    v (generate PO grouped by ee06)
[[tgm01]] (Purchase Orders)
    |
    +--- ga2301 = fa01 (link back to order)
    |
    v
[[tgm02]] (PO Lines)
    |
    +--- gb2601 = fa01 (link back to order)
    +--- gb09 = calculated qty
```

---

## Common Queries

### Get Quotation with Items

```sql
SELECT
    q.ea01 AS [Quotation],
    q.ea02 AS [Customer],
    q.ea03 AS [Date],
    qd.eb03 AS [Product],
    qd.eb05 AS [Qty],
    qd.eb07 AS [Price],
    qd.eb10 AS [Amount]
FROM [[tem01]] q
INNER JOIN [[tem02]] qd ON qd.eb01 = q.ea01
WHERE q.ea01 = @QuotationNo
ORDER BY qd.eb02
```

### Get Order BOM

```sql
SELECT
    b.ee011 AS [Order],
    b.ee02 AS [Product],
    b.ee03 AS [Component],
    b.ee06 AS [Supplier],
    b.ee04 AS [Ratio_Num],
    b.ee05 AS [Ratio_Denom],
    b.ee10 AS [MainPart]
FROM [[tem05]] b
WHERE b.ee011 = @OrderNo
ORDER BY b.ee02, b.ee07
```

### Trace BOM to Purchases

```sql
-- Full trace from order BOM to purchase orders
SELECT
    b.ee011 AS [Order],
    b.ee02 AS [Product],
    b.ee03 AS [Component],
    b.ee06 AS [Supplier],
    od.fb09 AS [Order_Qty],
    CAST((od.fb09 * b.ee04 / b.ee05) AS DECIMAL(10,2)) AS [Required_Qty],
    p.ga01 AS [PO_No],
    pd.gb09 AS [PO_Qty]
FROM [[tem05]] b
INNER JOIN [[tfm02]] od ON od.fb01 = b.ee011 AND od.fb03 = b.ee02
LEFT JOIN [[tgm01]] p ON p.ga2301 = b.ee011 AND p.ga04 = b.ee06
LEFT JOIN [[tgm02]] pd ON pd.gb01 = p.ga01 AND pd.gb04 = b.ee03
WHERE b.ee011 = @OrderNo
ORDER BY b.ee06, b.ee03
```

---

## Navigation

- **Previous**: `./05-tdm.md` (Product Master)
- **Next**: `./07-tfm.md` (Sales Order)
- **Index**: `./_index.yaml`
- **Overview**: `./00-overview.md`
