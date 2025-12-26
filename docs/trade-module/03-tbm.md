# TBM - Customer Master

```yaml
---
module_id: tbm
name_zh: "客戶主檔"
name_en: "Customer Master"
table_range: tbm01-tbm23
field_prefix: "b{table_char}{seq}"
layer: master_data
tables: 23
primary_key: "[[tbm01.ba01]]"
index: "./_index.yaml"
---
```

## Module Overview

TBM manages customer master data including company info, contacts, addresses, and customer-specific product configurations. The primary key `[[tbm01.ba01]]` is referenced throughout all transaction modules.

---

## Table Registry

| Table | Purpose | Primary Key |
|-------|---------|-------------|
| tbm01 | **Customer master** | `ba01` |
| tbm02 | Customer contacts | `(bb01, bb02)` |
| tbm03 | Customer addresses | `(bc01, bc02)` |
| tbm04 | Customer bank info | `(bd01, bd02)` |
| tbm05 | Customer-product link | `(be01, be02)` |
| tbm06 | Customer price level | `(bf01, bf02)` |
| tbm07 | Payment history | `(bg01, bg02)` |
| tbm08-10 | Credit management | - |
| tbm11-15 | Customer categories | - |
| tbm16-20 | Customer preferences | - |
| tbm21-23 | Reserved | - |

---

## TBM01 - Customer Master

### Field Definition

```yaml
table: tbm01
name: "Customer Master"
primary_key: ba01
total_fields: ~50
```

| Field | Type | Description | Referenced By |
|-------|------|-------------|---------------|
| `ba01` | varchar(10) | **Customer code** (PK) | `[[tfm01.fa04]]`, `[[tem01.ea02]]`, `[[thm01.ha04]]` |
| `ba02` | varchar(50) | Customer name | |
| `ba03` | varchar(100) | Address line 1 | |
| `ba04` | varchar(100) | Address line 2 | |
| `ba05` | varchar(10) | Country | |
| `ba06` | varchar(20) | Phone | |
| `ba07` | varchar(50) | Email | |
| `ba08` | varchar(5) | Currency preference | `[[tam08.ha01]]` |
| `ba09` | varchar(10) | Payment terms | `[[tam11]]` |
| `ba10` | varchar(10) | Sales rep | |
| `ba11` | float | Credit limit | |
| `ba12` | char(1) | Active (Y/N) | |

---

## TBM02 - Customer Contacts

```yaml
table: tbm02
name: "Customer Contacts"
primary_key: "(bb01, bb02)"
```

| Field | Type | Description |
|-------|------|-------------|
| `bb01` | varchar(10) | **Customer code** -> `[[tbm01.ba01]]` |
| `bb02` | int | Contact sequence |
| `bb03` | varchar(30) | Contact name |
| `bb04` | varchar(30) | Title/Position |
| `bb05` | varchar(20) | Phone |
| `bb06` | varchar(50) | Email |
| `bb07` | char(1) | Primary contact (Y/N) |

---

## TBM05 - Customer-Product Link

```yaml
table: tbm05
name: "Customer-specific Product Settings"
primary_key: "(be01, be02)"
purpose: "Customer-specific product codes, pricing"
```

| Field | Type | Description |
|-------|------|-------------|
| `be01` | varchar(10) | **Customer code** -> `[[tbm01.ba01]]` |
| `be02` | varchar(20) | **Product code** -> `[[tdm01.da01]]` |
| `be03` | varchar(30) | Customer's product code |
| `be04` | varchar(50) | Customer's product name |
| `be05` | float | Customer-specific price |
| `be06` | varchar(5) | Currency |

---

## Cross-Module References

### Customer Reference Chain

```yaml
master: "[[tbm01.ba01]]"
referenced_by:
  tem: "[[tem01.ea02]] - Quotation customer"
  tfm: "[[tfm01.fa04]] - Order customer"
  thm: "[[thm01.ha04]] - Invoice customer"
  tlm: "[[tlm01.customer]] - AR customer"
  tgm: "[[tgm01.ga13]] - Indirect (order's customer)"
```

### Data Flow

```
[[tbm01.ba01]] (Customer Master)
      |
      +---> [[tem01.ea02]] (Quotation)
      |           |
      |           v
      +---> [[tfm01.fa04]] (Order)
      |           |
      |           v
      +---> [[thm01.ha04]] (Invoice)
                  |
                  v
            [[tlm01]] (AR)
```

---

## Common Queries

### Get Customer with Orders

```sql
SELECT
    c.ba01 AS [Customer],
    c.ba02 AS [Name],
    COUNT(o.fa01) AS [Order_Count],
    SUM(o.fa25) AS [Total_Amount]
FROM [[tbm01]] c
LEFT JOIN [[tfm01]] o ON o.fa04 = c.ba01
WHERE c.ba12 = 'Y'  -- Active customers
GROUP BY c.ba01, c.ba02
ORDER BY [Total_Amount] DESC
```

### Get Customer Products

```sql
SELECT
    c.ba01 AS [Customer],
    cp.be02 AS [Product_Code],
    cp.be03 AS [Customer_PN],
    cp.be05 AS [Customer_Price],
    d.da02 AS [Product_Name]
FROM [[tbm01]] c
INNER JOIN [[tbm05]] cp ON cp.be01 = c.ba01
INNER JOIN [[tdm01]] d ON d.da01 = cp.be02
WHERE c.ba01 = @CustomerCode
```

---

## Navigation

- **Previous**: `./02-tsm.md` (Runtime Parameters)
- **Next**: `./04-tcm.md` (Supplier Master)
- **Index**: `./_index.yaml`
