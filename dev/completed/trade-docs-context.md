# Trade Module Documentation - Context

**Last Updated**: 2025-12-26
**Status**: In Progress

---

## Completed Files

```
docs/trade-module/
  _index.yaml        [DONE] - Module registry and field mappings
  _auxiliary.md      [DONE] - Support modules (tlm, tqm, tmm, trm, tjm, tpm, tnm, tam, tsm)
  00-overview.md     [DONE] - Complete business flow overview
  01-tam.md          [DONE] - System Settings (26 tables)
  02-tsm.md          [DONE] - Runtime Parameters (15 tables)
  03-tbm.md          [DONE] - Customer Master (23 tables)
  04-tcm.md          [DONE] - Supplier Master (15 tables)
  05-tdm.md          [DONE] - Product Master (26 tables, includes BOM)
  06-tem.md          [DONE] - Quotation (17 tables)
  07-tfm.md          [DONE] - Sales Order module
  08-tgm.md          [DONE] - Purchase Order module
  09-thm.md          [DONE] - Shipment/INV/PKG module
```

## ALL DOCUMENTATION COMPLETE

## Documentation Structure

Using `[[table.field]]` notation for cross-references.
Each module doc follows same YAML frontmatter structure.

## Key Findings Already Documented

1. **Field Reference Convention**: `[[tfm01.fa01]]` format
2. **Primary Keys**:
   - tbm01: ba01 (customer)
   - tcm01: ca01 (supplier)
   - tdm01: da01 (product)
   - tem01: ea01 (quotation)
   - tfm01: fa01 (order)
   - tgm01: ga01 (purchase)
   - thm01: ha01 (shipment)

3. **Critical Link Fields**:
   - `[[tgm01.ga2301]]` -> `[[tfm01.fa01]]` (P/O to S/C)
   - `[[tgm02.gb2601]]` -> `[[tfm01.fa01]]` (P/O line to S/C)
   - `[[tem05.ee011]]` = Order BOM identifier

4. **BOM Formula**:
   ```
   Component_Qty = Order_Qty * (ee04 / ee05)
   ```

## Status: COMPLETE

All 12 documentation files have been created:
- 2 reference files (_index.yaml, _auxiliary.md)
- 1 overview (00-overview.md)
- 9 module docs (01-tam through 09-thm)

## Next Steps

1. Git commit
2. Archive this context file to dev/completed/
