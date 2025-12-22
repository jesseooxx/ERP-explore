# DataWin ERP 系統逆向工程分析報告

## 1. 系統識別

| 項目 | 內容 |
|------|------|
| **軟體名稱** | DataWin EXPERT 2014 / ERP 2014 |
| **開發商** | DataWin (大華軟體) |
| **技術架構** | Windows 桌面應用 (Delphi) + SQL Server |
| **部署方式** | 網路共享部署 (Client-Server) |
| **語言支援** | 繁體中文、簡體中文、英文 |
| **分析日期** | 2025-12-18 |

---

## 2. X:\ 磁碟整體架構

```
X:\  (網路磁碟 - ERP 伺服器共享)
│
├── DATA/                    ← 通訊錄/聯絡人資料庫 (DAT/IDX 格式)
│   ├── ADDR.DAT/IDX         (地址資料庫 ~3 MB)
│   ├── nwAddr.dat/idx       (網路地址 ~61 MB)
│   ├── NAME.DAT/IDX         (名稱資料)
│   ├── KWORD1/2.DAT/IDX     (關鍵字索引)
│   └── F1Help.dat           (說明系統)
│
├── Driver/                  ← 印表機與網路軟體驅動
│   ├── Epson 1390 Driver/
│   ├── FileZilla/           (Client + Server)
│   ├── FX DocuPrint C1110 B PCL 6/
│   ├── PrintServer/
│   └── Xerox/
│
├── EXE/                     ← 主程式目錄 (核心！)
│   ├── *.dll                (500+ 功能模組)
│   ├── *.bpl                (14 個 Borland Package)
│   ├── *.chm                (6 個說明文件 ~130 MB)
│   ├── *.dat                (設定/資料檔)
│   ├── FASTREPORT/          (報表範本)
│   ├── XML/                 (資料交換格式)
│   ├── pageform/            (表單定義)
│   └── SCRIPT/              (腳本檔案)
│
├── NETSETUP/                ← 網路安裝套件
│   └── SQL_NET_EXPERT2014/
│       ├── MsiStub/{GUID}/
│       │   └── DATAWIN EXPERT 2014 Setup.msi
│       └── setup/
│           ├── setup.exe
│           ├── data1.cab + data2.cab (~28 MB)
│           └── setupdir/ (多語言)
│
├── source/                  ← 原始碼與發行版本
│   ├── 2014EXPERT1403/
│   ├── 2014_ALLERPSP_2001/
│   ├── sn20010201~sn20011001/  (2020/01 版本)
│   ├── sn20020701/             (2020/02 版本)
│   ├── sn20030101~sn20031001/  (2020/03 版本)
│   ├── sn20040201~sn20041001/  (2020/04 版本)
│   └── *.sql                   (68+ SQL 腳本)
│
├── 查詢軟體/                ← 空資料夾（已遷移）
├── setup_erp2014.cmd        ← ERP 相容性安裝腳本
└── TeamViewerQS_zhtw.exe    ← 遠端支援工具
```

---

## 3. 主要功能模組

### 3.1 DLL 模組命名規則

從 DLL 檔名可以識別出各個功能模組：

| 前綴 | 模組名稱 | DLL 範例 | 說明 |
|------|---------|---------|------|
| `xPa` | 應付帳款 | xPa1i01.dll | Accounts Payable |
| `xPb` | 應收帳款 | xPb1i01.dll | Accounts Receivable |
| `xPc` | 成本會計 | xPc1i01.dll | Cost Accounting |
| `xPe` | 採購管理 | xPe1i01.dll | Procurement |
| `xPf` | 財務管理 | xPf1i01.dll | Finance |
| `xPg` | 總帳 | xPg1i01.dll | General Ledger |
| `xPk` | 庫存管理 | xPk1i01.dll | Inventory |
| `xPl` | 物流管理 | xPl1i01.dll | Logistics |
| `xPs` | 薪資管理 | xPs1i01.dll | Salary/Payroll |
| `xSa`-`xSc` | 銷售管理 | xSa1i01.dll | Sales |
| `xKt`-`xKs` | 生產製造 | xKt1i01.dll | Manufacturing |
| `xnf` | 固定資產 | xnfa1i01.dll | Fixed Assets |
| `xns` | 序號管理 | xnsb1i01a.dll | Serial Numbers |
| `xtf` | 運輸物流 | xtf1i01.dll | Transportation |

### 3.2 CHM 說明文件

| 檔案 | 大小 | 檔案數 | 模組 |
|-----|------|-------|------|
| GOLDENTOP_1.chm | 67 MB | 1,461 | 主系統 (全模組整合) |
| stock_1.chm | 21 MB | 510 | 庫存管理 |
| Acct_1.chm | 12 MB | 303 | 會計總帳 |
| prod_1.chm | 11 MB | 221 | 生產製造 |
| salary_1.chm | 10 MB | 224 | 薪資管理 |
| trade_1.chm | 6 MB | 287 | 貿易管理 |

---

## 4. 資料庫概覽

### 4.1 SQL 腳本統計

| 類型 | 數量 | 大小 | 說明 |
|-----|------|------|------|
| proc.sql | 9 版本 | ~39 MB/個 | 存儲程序 (~798,000 行) |
| trigger.sql | 9 版本 | ~1.8 MB/個 | 觸發器 (~58,800 行) |
| view.sql | 9 版本 | ~150 KB/個 | 檢視表 |
| create_table_*.sql | 17 個 | ~50 KB | 建表腳本 |
| add_column_*.sql | 20+ 個 | ~30 KB | 欄位擴充 |

### 4.2 資料庫物件統計

| 物件類型 | 數量 | 主要類別 |
|---------|------|---------|
| 存儲程序/函數 | ~2,952 個 | Calculate_*, DLL_*, fn_*, sp_* |
| 觸發器 | ~50+ 個 | UPDATE/DELETE 監控 |
| 檢視表 | ~30+ 個 | VCustomer, V_Trade_Stock_* |
| MRP 函數 | ~30+ 個 | fn_MRP_* (物料需求計劃) |

---

## 5. 技術架構

### 5.1 開發技術棧

```
┌─────────────────────────────────────────────────────┐
│                    用戶介面層                        │
│           Delphi VCL (*.bpl, *.dll)                 │
├─────────────────────────────────────────────────────┤
│                    業務邏輯層                        │
│         DLL 模組 + 存儲程序 (sp_*, DLL_*)           │
├─────────────────────────────────────────────────────┤
│                    資料存取層                        │
│              SQL Server + ADO/BDE                   │
├─────────────────────────────────────────────────────┤
│                    資料儲存層                        │
│     SQL Server DB + DAT/IDX 檔案 + FastReport      │
└─────────────────────────────────────────────────────┘
```

### 5.2 部署架構

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Client PC   │     │  Client PC   │     │  Client PC   │
│  (ERP 用戶端) │     │  (ERP 用戶端) │     │  (ERP 用戶端) │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                    ┌───────┴───────┐
                    │   X:\ 網路磁碟  │
                    │  (ERP 伺服器)   │
                    ├───────────────┤
                    │  EXE/ (程式)   │
                    │  DATA/ (資料)  │
                    │  source/ (原始碼)│
                    └───────┬───────┘
                            │
                    ┌───────┴───────┐
                    │  SQL Server   │
                    │   資料庫伺服器  │
                    └───────────────┘
```

---

## 6. 多客戶定制架構

系統支援多個客戶的定制化需求，透過專用資料表實現：

| 客戶代碼 | 資料表前綴 | 說明 |
|---------|-----------|------|
| 旺品 | wangpin_kqm* | 商品認證、路由設定 |
| 中規 | zhonggui_kqm* | 供應商設定 |
| 裝盟 | zhuangmeng_kqm* | 供應商設定 |
| 食恆 | shiheng_kqm* | 供應商設定 |
| 奇異 | qiyi_pos_* | POS 終端整合 |
| 德保清 | DeBaoQing_tqm* | 擔保清單 |

---

## 7. 逆向工程建議

### 7.1 推薦工具

| 工具 | 用途 |
|-----|------|
| IDR (Interactive Delphi Reconstructor) | Delphi DLL 反編譯 |
| IDA Pro / Ghidra | 通用反組譯 |
| SQL Server Management Studio | 資料庫分析 |
| 7-Zip | CHM 解壓 |
| DB Browser | DAT/IDX 檔案查看 |

### 7.2 分析優先順序

1. **SQL 存儲程序** - 核心業務邏輯
2. **DLL 匯出函數** - API 介面
3. **CHM 說明文件** - 功能說明
4. **DAT/IDX 格式** - 資料結構

---

## 附錄：相關文件

- `02_SQL結構詳細說明.md` - SQL 資料庫完整結構
- `CHM_PDF/` - CHM 轉換後的 PDF 說明文件
