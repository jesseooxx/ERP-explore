# TSM - Runtime Parameters

```yaml
---
module_id: tsm
name_zh: "運作參數"
name_en: "Runtime Parameters"
table_range: tsm01-tsm13
field_prefix: "{varies}"
layer: configuration
scope: module
tables: 15
index: "./_index.yaml"
---
```

## Module Overview

TSM stores runtime parameters and conversion factors used during transaction processing. Unlike TAM (static config), TSM values may change based on operational needs.

---

## Table Registry

| Table | Purpose | Example Values |
|-------|---------|----------------|
| tsm01 | **System startup params** | IC15=35.315 (CBM to CUFT) |
| tsm02 | Number formats | decimal places, separators |
| tsm03 | **Unit conversion** | PCS <-> BOX <-> PALLET |
| tsm04 | **Report formats** | INVOICE template, Packing List |
| tsm05 | Print settings | printer, margins |
| tsm06 | Auto-numbering seeds | current sequence numbers |
| tsm07 | Calculation modes | rounding, precision |
| tsm08-09 | Reserved | - |
| tsm10 | **Document numbering rules** | prefix, suffix, length |
| tsm11-13 | Module-specific params | varies |

---

## Key Tables

### TSM01 - System Parameters

```yaml
table: tsm01
purpose: "Core calculation parameters"
```

| Parameter | Value | Usage |
|-----------|-------|-------|
| IC15 | 35.315 | CBM to CUFT conversion factor |
| IC16 | 2.205 | KG to LBS conversion factor |
| IC20 | Y/N | Auto-create AR on shipment |
| IC21 | Y/N | Auto-create AP on PO |

### TSM03 - Unit Conversion

```yaml
table: tsm03
purpose: "Unit of measure conversions"
```

| From | To | Factor | Used In |
|------|-----|--------|---------|
| PCS | BOX | variable | `[[thm03]]` packing |
| BOX | PALLET | variable | shipping |
| KG | LBS | 2.205 | weight display |
| CBM | CUFT | 35.315 | volume display |

### TSM04 - Report Formats

```yaml
table: tsm04
purpose: "Document template definitions"
```

| Format Code | Document | Template Fields |
|-------------|----------|-----------------|
| INV01 | INVOICE | header, lines, totals |
| PKG01 | PACKING LIST | boxes, weights, dims |
| MRK01 | SHIPPING MARK | logo, text blocks |
| SC01 | Sales Contract | terms, items |
| PO01 | Purchase Order | supplier, items |

### TSM10 - Document Numbering

```yaml
table: tsm10
purpose: "Auto-numbering rules for documents"
```

| Doc Type | Pattern | Example |
|----------|---------|---------|
| PI | {YY}{MM}{NNNN} | 2512-0001 |
| PO | {PI}-{NN} | 00048-01 |
| INV | {YY}{MM}-{NNNN} | 2512-0001 |

---

## Cross-Module Usage

```yaml
used_by:
  tfm:
    - "tsm10 -> PI number generation"
    - "tsm04 -> PI print format"
  tgm:
    - "tsm10 -> PO number generation"
    - "tsm04 -> PO print format"
  thm:
    - "tsm01.IC15 -> CBM calculation"
    - "tsm03 -> unit conversions for packing"
    - "tsm04 -> INVOICE, PKG, MARK formats"
```

---

## Relationship with TAM

```yaml
configuration_layers:
  tam:
    scope: "Global, rarely changed"
    examples: "Company info, currencies, ports"
  tsm:
    scope: "Operational, may change"
    examples: "Number formats, conversion factors, templates"
```

---

## Navigation

- **Previous**: `./01-tam.md` (System Settings)
- **Next**: `./03-tbm.md` (Customer Master)
- **Index**: `./_index.yaml`
