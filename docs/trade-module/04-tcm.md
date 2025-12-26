# TCM - Supplier Master

```yaml
---
module_id: tcm
name_zh: "供應商主檔"
name_en: "Supplier Master"
table_range: tcm01-tcm15
field_prefix: "c{table_char}{seq}"
layer: master_data
tables: 15
primary_key: "[[tcm01.ca01]]"
index: "./_index.yaml"
---
```

## Module Overview

TCM manages supplier master data and supplier-product relationships. The primary key `[[tcm01.ca01]]` links to purchase orders and BOM definitions.

---

## Table Registry

| Table | Purpose | Primary Key |
|-------|---------|-------------|
| tcm01 | **Supplier master** | `ca01` |
| tcm02 | Supplier contacts | `(cb01, cb02)` |
| tcm03 | Supplier addresses | `(cc01, cc02)` |
| tcm04 | Supplier bank info | `(cd01, cd02)` |
| tcm05 | **Supplier-product link** | `(ce010, ce011, ce02, ce04)` |
| tcm06 | Supplier price history | - |
| tcm07 | Supplier performance | - |
| tcm08-15 | Reserved/Misc | - |

---

## TCM01 - Supplier Master

### Field Definition

```yaml
table: tcm01
name: "Supplier Master"
primary_key: ca01
total_fields: ~45
```

| Field | Type | Description | Referenced By |
|-------|------|-------------|---------------|
| `ca01` | varchar(10) | **Supplier code** (PK) | `[[tgm01.ga04]]`, `[[tem05.ee06]]`, `[[tdm05.de05]]` |
| `ca02` | varchar(50) | Supplier name | |
| `ca03` | varchar(100) | Address line 1 | |
| `ca04` | varchar(100) | Address line 2 | |
| `ca05` | varchar(10) | Country | |
| `ca06` | varchar(20) | Phone | |
| `ca07` | varchar(50) | Email | |
| `ca08` | varchar(5) | Currency | `[[tam08.ha01]]` |
| `ca09` | varchar(10) | Payment terms | |
| `ca10` | int | Lead time (days) | |
| `ca11` | char(1) | Active (Y/N) | |

---

## TCM05 - Supplier-Product Link

### Field Definition

```yaml
table: tcm05
name: "Supplier-Product Relationship"
primary_key: "(ce010, ce011, ce02, ce04)"
purpose: "Links products to suppliers with pricing"
```

| Field | Type | Description |
|-------|------|-------------|
| `ce010` | varchar(10) | **Supplier code** -> `[[tcm01.ca01]]` |
| `ce011` | varchar(10) | Qualifier |
| `ce02` | varchar(20) | **Product/Component code** -> `[[tdm01.da01]]` |
| `ce03` | varchar(30) | Supplier's part number |
| `ce04` | int | Sequence |
| `ce05` | float | Unit price |
| `ce06` | varchar(5) | Currency |
| `ce07` | int | MOQ (Min Order Qty) |
| `ce08` | int | Lead time (days) |

---

## Cross-Module References

### Supplier Reference Chain

```yaml
master: "[[tcm01.ca01]]"
referenced_by:
  tdm: "[[tdm05.de05]] - Standard BOM supplier"
  tem: "[[tem05.ee06]] - Order BOM supplier"
  tgm: "[[tgm01.ga04]] - Purchase Order supplier"
  tlm: "[[tlm09.supplier]] - AP supplier"
```

### Data Flow

```
[[tcm01.ca01]] (Supplier Master)
      |
      +---> [[tdm05.de05]] (Standard BOM)
      |           |
      |           v (copy on order creation)
      +---> [[tem05.ee06]] (Order BOM)
      |           |
      |           v (generate PO)
      +---> [[tgm01.ga04]] (Purchase Order)
                  |
                  v (auto-create on save)
            [[tlm09]] (AP)
```

---

## Relationship with BOM

### Standard BOM (tdm05)

```yaml
table: "[[tdm05]]"
pk: "(de01, de02)"
supplier_field: "[[tdm05.de05]]"
usage: "Default supplier for each component"
```

### Order BOM (tem05)

```yaml
table: "[[tem05]]"
pk: "(ee011, ee02, ee03)"
supplier_field: "[[tem05.ee06]]"
usage: "Order-specific supplier (may differ from standard)"
trigger: "Copied from [[tdm05]] when order created"
```

---

## Common Queries

### Get Supplier with Products

```sql
SELECT
    s.ca01 AS [Supplier],
    s.ca02 AS [Name],
    sp.ce02 AS [Product],
    sp.ce05 AS [Price],
    sp.ce08 AS [LeadTime]
FROM [[tcm01]] s
INNER JOIN [[tcm05]] sp ON sp.ce010 = s.ca01
WHERE s.ca11 = 'Y'  -- Active suppliers
ORDER BY s.ca01, sp.ce02
```

### Get Supplier Purchase History

```sql
SELECT
    s.ca01 AS [Supplier],
    s.ca02 AS [Name],
    COUNT(p.ga01) AS [PO_Count],
    SUM(p.ga37) AS [Total_Amount]
FROM [[tcm01]] s
LEFT JOIN [[tgm01]] p ON p.ga04 = s.ca01
WHERE s.ca11 = 'Y'
GROUP BY s.ca01, s.ca02
ORDER BY [Total_Amount] DESC
```

### Find Suppliers for Component

```sql
SELECT
    sp.ce010 AS [Supplier],
    s.ca02 AS [Supplier_Name],
    sp.ce03 AS [Supplier_PN],
    sp.ce05 AS [Price],
    sp.ce07 AS [MOQ],
    sp.ce08 AS [LeadTime]
FROM [[tcm05]] sp
INNER JOIN [[tcm01]] s ON s.ca01 = sp.ce010
WHERE sp.ce02 = @ComponentCode
ORDER BY sp.ce05  -- by price
```

---

## Navigation

- **Previous**: `./03-tbm.md` (Customer Master)
- **Next**: `./05-tdm.md` (Product Master)
- **Index**: `./_index.yaml`
