# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Critical Safety Rule

**嚴格絕對禁止對 X:\ 裡面所有的檔案進行直接的修改或讀寫**
要調查、修改、覆寫、監控的話務必先備份並且處理備份的檔案

## Project Overview

ERP-explore is a research project for reverse-engineering and automating the DataWin ERP system (大華軟體 EXPERT 2014). The project covers:
- SQL database schema analysis and direct data injection
- DLL-based report rendering (bypassing slow GUI)
- Trade module documentation and workflow mapping

## Architecture

```
ERP-explore/
├── docs/                    # ERP documentation
│   ├── trade-module/        # T-module docs (TAM→TSM→TBM→TDM→TEM→TFM→TGM→THM)
│   └── erp-manuals/         # CHM-to-PDF converted manuals
├── nrp32_renderer/          # Native DLL PDF renderer (32-bit Python required)
├── sql/                     # SQL scripts and Python query tools
├── src/                     # Utility scripts (CHM conversion, data extraction)
├── research/                # Reverse engineering research notes
├── reverse_engineering/     # DLL analysis and binary inspection tools
└── dev/                     # Task management (active/completed)
```

## Common Commands

### Database Queries (Local SQL Server)
```bash
# Test connection and query trade tables
python sql/query_trade_schema.py

# Query specific product details
python sql/query_product_detail.py
```

### TMP to PDF Rendering (requires 32-bit Python)
```bash
# Using Python launcher for 32-bit
py -3.12-32 nrp32_renderer/render_to_pdf_enhanced.py input.tmp output.pdf

# With custom DPI (default is 150)
py -3.12-32 nrp32_renderer/render_to_pdf_enhanced.py input.tmp output.pdf 300

# Check if 32-bit Python is available
py -3.12-32 -c "import struct; print(f'{struct.calcsize(\"P\") * 8}-bit')"
```

### SQL Scripts (run in SSMS)
```sql
-- auto_insert_test.sql      Test order injection
-- calculate_bom_quantities.sql   Verify BOM calculations
-- create_product_bom.sql    Create product assembly records
```

## Key Technical Details

### Database Connection
```python
# Connection via pyodbc (Windows auth)
"DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=DATAWIN;Trusted_Connection=yes;"
```

### Trade Module Table Naming
| Prefix | Module | Purpose |
|--------|--------|---------|
| tfm01/02 | Sales Order (PI) | Order master/detail |
| tdm01/05 | Product | Product master/BOM assembly |
| tem01/02/05 | Quotation | Quote master/detail/assembly |
| tgm01/02 | Purchase Order | PO master/detail |
| thm01/02 | Shipment | Shipping master/detail |

### BOM Calculation Formula
```
Component Quantity = Order Qty × (Numerator / Denominator)
Flow: tdm05 (standard BOM) → tem05 (order BOM) → tgm01/02 (purchase order)
```

### 32-bit DLL Requirements
The nrp32_renderer module requires 32-bit Python due to legacy Borland C++ DLLs:
- WNrpDll.dll, NrpDll.dll, MakeReport.dll (main renderer)
- nview32.dll, borlndmm.dll, cc32110mt.dll (dependencies)

DLLs should be in `X:/EXE/` or `nrp32_renderer/dll/` for local development.

## Important Paths

| Resource | Location |
|----------|----------|
| ERP Server | X:\ (network share - READ ONLY!) |
| SQL Backup | D:\SQL備份\BK7.bak |
| DLL Source | X:/EXE/*.dll |
| Local DB | localhost/DATAWIN |

## Documentation References

- **Quick Start for Injection**: `docs/直接注入操作指南.md`
- **Table Relationships**: `docs/完整資料表關聯圖.md`
- **T-Module Overview**: `docs/trade-module/00-overview.md`
- **Research Summary**: `research/00_研究總結報告.md`
