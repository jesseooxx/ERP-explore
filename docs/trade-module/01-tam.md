# TAM - System Settings

```yaml
---
module_id: tam
name_zh: "系統設定"
name_en: "System Settings"
table_range: tam01-tam26
field_prefix: "{varies}"
layer: configuration
scope: global
tables: 26
index: "./_index.yaml"
---
```

## Module Overview

TAM provides global system configuration including company info, user management, currency settings, and location data. These settings are referenced by all transaction modules.

---

## Table Registry

| Table | Purpose | Key Fields |
|-------|---------|------------|
| tam01 | Company info | company_code, name, address |
| tam02 | Branch/department | branch_code, dept_name |
| tam03 | System flags | feature toggles |
| tam04 | Document templates | doc_type, template_path |
| tam05 | User master | user_id, password, permissions |
| tam06 | User groups | group_id, group_name |
| tam07 | Access control | user_id, module, permission_level |
| tam08 | **Currency master** | ha01 (code), exchange_rate |
| tam09 | Exchange rate history | currency, date, rate |
| tam10 | Bank master | bank_code, bank_name, swift |
| tam11 | Payment terms | term_code, days, description |
| tam12 | Shipment methods | method_code, description |
| tam13-16 | Reserved | - |
| tam17 | **Ports/Countries** | port_code, country, port_name |
| tam18-20 | Trade terms | incoterms, definitions |
| tam21-26 | Misc settings | various system configs |

---

## Key Tables

### TAM08 - Currency Master

```yaml
table: tam08
purpose: "Currency codes and exchange rates"
primary_key: ha01
```

| Field | Type | Description | Referenced By |
|-------|------|-------------|---------------|
| `ha01` | varchar(5) | **Currency code** (USD, TWD, etc.) | `[[tfm01.fa19]]`, `[[tgm01.ga06]]`, `[[thm01.ha19]]` |
| `ha02` | varchar(20) | Currency name | |
| `ha03` | float | Exchange rate to base | |
| `ha04` | char(1) | Active flag | |

### TAM17 - Ports/Countries

```yaml
table: tam17
purpose: "Port and country reference data"
```

| Field | Type | Description | Referenced By |
|-------|------|-------------|---------------|
| port_code | varchar(10) | Port identifier | `[[tfm01.fa11]]`, `[[tfm01.fa14]]` |
| country | varchar(10) | Country code | |
| port_name | varchar(50) | Port full name | |

---

## Cross-Module References

```yaml
provides_to:
  tfm:
    - "[[tam08.ha01]] -> [[tfm01.fa19]] (order currency)"
    - "[[tam17]] -> [[tfm01.fa11]], [[tfm01.fa14]] (ports)"
  tgm:
    - "[[tam08.ha01]] -> [[tgm01.ga06]] (PO currency)"
  thm:
    - "[[tam08.ha01]] -> [[thm01.ha19]] (invoice currency)"
  all_modules:
    - "[[tam05]] -> user authentication"
    - "[[tam01]] -> company header info"
```

---

## Navigation

- **Next**: `./02-tsm.md` (Runtime Parameters)
- **Index**: `./_index.yaml`
- **Overview**: `./00-overview.md`
