# TDM - Product Master

```yaml
---
module_id: tdm
name_zh: "產品主檔"
name_en: "Product Master"
table_range: tdm01-tdm26
field_prefix: "d{table_char}{seq}"
layer: master_data
tables: 26
primary_key: "[[tdm01.da01]]"
index: "./_index.yaml"
---
```

## Module Overview

TDM is the core product master module containing product info, standard BOM, pricing, and packaging data. The primary key `[[tdm01.da01]]` is referenced throughout all transaction modules.

**Key Feature**: Standard BOM in `[[tdm05]]` is copied to Order BOM `[[tem05]]` when creating orders.

---

## Table Registry

| Table | Purpose | Primary Key |
|-------|---------|-------------|
| tdm01 | **Product master** (85 fields) | `da01` |
| tdm02 | Product sub-descriptions | `(db01, db02)` |
| tdm03 | Product images | `(dc01, dc02)` |
| tdm04 | Product categories | `dd01` |
| tdm05 | **Standard BOM** (19 fields) | `(de01, de02)` |
| tdm06 | BOM alternatives | - |
| tdm07 | Product specs | - |
| tdm08 | **Packaging data** | `(dh01, dh02)` |
| tdm09 | **Price levels** | `(di01, di02)` |
| tdm10-15 | Product attributes | - |
| tdm16-20 | Reserved | - |
| tdm21-26 | Extended data | - |

---

## TDM01 - Product Master

### Field Definition

```yaml
table: tdm01
name: "Product Master"
total_fields: 85
primary_key: da01
```

| Field | Type | Description | Referenced By |
|-------|------|-------------|---------------|
| `da01` | varchar(20) | **Product code** (PK) | `[[tdm05.de01]]`, `[[tem02.eb03]]`, `[[tfm02.fb03]]`, `[[tgm02.gb03]]`, `[[thm02.hb02]]` |
| `da02` | varchar(50) | Product name 1 | |
| `da03` | varchar(50) | Product name 2 | |
| `da04` | varchar(10) | Category code | `[[tdm04.dd01]]` |
| `da05` | varchar(6) | Unit of measure | |
| `da06` | float | Net weight | |
| `da07` | float | Gross weight | |
| `da08` | float | Volume (CBM) | |
| `da09` | float | Standard cost | |
| `da10` | float | Standard price | |
| `da11` | varchar(10) | Default supplier | `[[tcm01.ca01]]` |
| `da12` | char(1) | Active (Y/N) | |

---

## TDM05 - Standard BOM (Critical)

### Field Definition

```yaml
table: tdm05
name: "Standard Bill of Materials"
total_fields: 19
primary_key: "(de01, de02)"
purpose: "Defines components and suppliers for each product"
```

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| `de01` | varchar(20) | **Product code** | `[[tdm01.da01]]` |
| `de02` | int | **Sequence** | PK part |
| `de03` | varchar(20) | Component code | `[[tdm01.da01]]` |
| `de04` | float | **Ratio numerator** | BOM calculation |
| `de05` | varchar(10) | **Supplier code** | `[[tcm01.ca01]]` |
| `de06` | float | **Ratio denominator** | BOM calculation |
| `de07` | float | Component price | |
| `de08` | varchar(6) | Unit | |
| `de09` | char(1) | Main part flag (Y/N) | |
| `de10` | varchar(50) | Component description | |

### BOM Calculation

```yaml
formula: "Component_Qty = Order_Qty * (de04 / de06)"
example:
  product: "WIDGET-A"
  order_qty: 1000
  component: "SCREW-01"
  de04: 4   # need 4 screws
  de06: 1   # per 1 product
  result: 4000  # purchase qty
```

### Copy Trigger

```yaml
trigger: "On [[tfm02]] insert (order line creation)"
action: "Copy [[tdm05]] to [[tem05]] for order-specific BOM"
mapping:
  - "[[tdm05.de01]] -> [[tem05.ee02]] (product)"
  - "[[tdm05.de02]] -> [[tem05.ee07]] (sequence)"
  - "[[tdm05.de03]] -> [[tem05.ee03]] (component)"
  - "[[tdm05.de04]] -> [[tem05.ee04]] (ratio num)"
  - "[[tdm05.de05]] -> [[tem05.ee06]] (supplier)"
  - "[[tdm05.de06]] -> [[tem05.ee05]] (ratio denom)"
  - "[[tfm01.fa01]] -> [[tem05.ee011]] (order no)"
```

---

## TDM08 - Packaging Data

### Field Definition

```yaml
table: tdm08
name: "Product Packaging Specifications"
primary_key: "(dh01, dh02)"
purpose: "Default packing dimensions for [[thm03]]"
```

| Field | Type | Description |
|-------|------|-------------|
| `dh01` | varchar(20) | **Product code** -> `[[tdm01.da01]]` |
| `dh02` | int | Package type sequence |
| `dh03` | int | Qty per inner carton |
| `dh04` | int | Inner per outer carton |
| `dh05` | float | Carton length (cm) |
| `dh06` | float | Carton width (cm) |
| `dh07` | float | Carton height (cm) |
| `dh08` | float | Net weight (kg) |
| `dh09` | float | Gross weight (kg) |

---

## TDM09 - Price Levels

### Field Definition

```yaml
table: tdm09
name: "Product Price Levels"
primary_key: "(di01, di02)"
```

| Field | Type | Description |
|-------|------|-------------|
| `di01` | varchar(20) | **Product code** -> `[[tdm01.da01]]` |
| `di02` | int | Price level (1-9) |
| `di03` | float | Unit price |
| `di04` | varchar(5) | Currency |
| `di05` | int | Min qty for this level |

---

## Cross-Module References

### Product Reference Chain

```yaml
master: "[[tdm01.da01]]"
referenced_by:
  tdm05: "[[tdm05.de01]] - Standard BOM"
  tem: "[[tem02.eb03]] - Quotation items"
  tfm: "[[tfm02.fb03]] - Order items"
  tgm: "[[tgm02.gb03]] - Purchase items"
  thm: "[[thm02.hb02]] - Invoice items"
```

### BOM Flow

```
[[tdm05]] (Standard BOM)
    |
    | [Order Creation Trigger]
    v
[[tem05]] (Order-specific BOM)
    |
    | ee011 = [[tfm01.fa01]] (Order No)
    | ee06 = Supplier
    |
    v
[[tgm01]]/[[tgm02]] (Purchase Order)
    |
    | Grouped by ee06 (Supplier)
    | Qty = [[tfm02.fb09]] * (ee04 / ee05)
```

---

## Common Queries

### Get Product with BOM

```sql
SELECT
    p.da01 AS [Product],
    p.da02 AS [Name],
    b.de02 AS [Seq],
    b.de03 AS [Component],
    b.de04 AS [Ratio_Num],
    b.de06 AS [Ratio_Denom],
    s.ca02 AS [Supplier]
FROM [[tdm01]] p
INNER JOIN [[tdm05]] b ON b.de01 = p.da01
LEFT JOIN [[tcm01]] s ON s.ca01 = b.de05
WHERE p.da01 = @ProductCode
ORDER BY b.de02
```

### Calculate Purchase Requirements

```sql
-- For a given order, calculate component requirements
SELECT
    b.de03 AS [Component],
    b.de05 AS [Supplier],
    SUM(CAST((od.fb09 * b.de04 / b.de06) AS DECIMAL(10,2))) AS [Required_Qty]
FROM [[tfm02]] od
INNER JOIN [[tem05]] b ON b.ee011 = od.fb01 AND b.ee02 = od.fb03
WHERE od.fb01 = @OrderNo
GROUP BY b.de03, b.de05
ORDER BY b.de05, b.de03
```

### Get Packaging Defaults

```sql
SELECT
    p.da01 AS [Product],
    pk.dh03 AS [Inner_Qty],
    pk.dh04 AS [Outer_Qty],
    pk.dh05 AS [Length],
    pk.dh06 AS [Width],
    pk.dh07 AS [Height],
    (pk.dh05 * pk.dh06 * pk.dh07 / 1000000) AS [CBM]
FROM [[tdm01]] p
INNER JOIN [[tdm08]] pk ON pk.dh01 = p.da01
WHERE p.da01 = @ProductCode
```

---

## Navigation

- **Previous**: `./04-tcm.md` (Supplier Master)
- **Next**: `./06-tem.md` (Quotation)
- **Index**: `./_index.yaml`
- **Related**: `./08-tgm.md` (uses BOM for purchase calculation)
