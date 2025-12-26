# Trade Module Flow Mapping - Tasks

## Last Updated: 2025-12-26

---

## Phase 1: 產品主檔欄位對應 ✅ COMPLETED

- [x] 查詢 tdm01 產品基本資料結構
- [x] 查詢 tdm02 產品子描述結構
- [x] 查詢 tdm05 產品BOM結構
- [x] 查詢 tdm09 售價等級結構
- [x] 查詢 tcm01 供應商基本資料結構
- [x] 查詢 tcm05 供應商產品關係結構
- [x] 查詢 tem01 報價單主檔結構
- [x] 查詢 tem02 報價單明細結構
- [x] 查詢 tem05 報價BOM結構
- [x] 查詢 tfm01 訂單主檔結構
- [x] 查詢 tfm02 訂單明細結構
- [x] 驗證 284102 產品資料
- [x] 更新文檔
- [x] 提交到 Git

---

## Phase 2: 訂單轉需求作業 ✅ COMPLETED

- [x] 查詢所有 t*m 系列資料表清單
- [x] 識別訂單轉需求相關表
  - [x] tfm03 產品出貨排程 - PK: (fc01, fc02, fc031..., fc04)
  - [x] tfm04 訂單出貨排程彙總 - PK: (fd01, fd02, fd03)
  - [x] tfm05 訂單選擇採購單 - PK: (fe01, fe03, fe04, fe07, fe25)
- [x] 查詢欄位結構
- [x] 找出與 tfm01/tfm02 的連動欄位
- [x] 記錄編號生成規則

---

## Phase 3: 出口採購作業 ✅ COMPLETED

- [x] 識別採購單相關表 (tgm 系列，非 tpm)
  - [x] tgm01 採購單主檔 (99欄位) - PK: ga01
  - [x] tgm02 採購單明細 (59欄位) - PK: (gb01, gb02)
  - [x] tgm03 採購分批 (26欄位)
  - [x] tgm04 採購彙總 (10欄位)
- [x] 查詢欄位結構
- [x] 找出與訂單的連動欄位: ga2301, gb2601 -> tfm01.fa01
- [x] 找出與供應商的連動欄位: ga04 -> tcm01.ca01
- [x] 記錄採購單編號規則: {S/C}-{seq}

---

## Phase 4: 船務出口出貨作業 ✅ COMPLETED

- [x] 識別出貨單相關表 (thm 系列)
  - [x] thm01 出貨單主檔 (141欄位) - PK: ha01
  - [x] thm02 出貨明細 (13欄位) - PK: (hb01, hb02)
  - [x] thm03 Packing 項目 (38欄位)
  - [x] thm04 Invoice 項目 (22欄位)
  - [x] thm06 Shipping Mark
- [x] 查詢欄位結構
- [x] 找出與訂單的連動欄位: ha04 -> tbm01.ba01 (customer)
- [x] 找出與採購單的連動欄位: 間接透過產品代碼
- [x] 記錄出貨單編號規則

---

## Phase 5: 編號連動關係圖 ✅ COMPLETED

- [x] 建立完整流程圖 -> docs/trade-module/00-overview.md
- [x] 標註所有單據編號格式
- [x] 標註欄位間的 FK 關係 -> docs/trade-module/_index.yaml
- [x] 標註狀態流轉
- [x] 驗證連動關係

---

## Phase 6: 文檔整理 ✅ COMPLETED

- [x] 建立文檔架構 docs/trade-module/
- [x] 建立索引檔 _index.yaml
- [x] 建立輔助模組彙整 _auxiliary.md
- [x] 建立主流程總覽 00-overview.md
- [x] 建立交易模組文檔 (07-tfm, 08-tgm, 09-thm)
- [x] 建立剩餘模組文檔 (01-tam ~ 06-tem)
- [ ] 提交到 Git

---

## Phase 7: 未文檔化模組研究 ✅ COMPLETED

- [x] tlm 帳款系列 (20表) - 應收應付，由 thm/tgm 自動觸發
- [x] tbm 客戶系列 (23表) - PK: ba01
- [x] tqm 規格/催貨 (26表) - 包含嘜頭模板、包裝規格
- [x] tmm 統計系列 (30表) - 最大表 tmm01 (72萬筆)
- [x] tam/tsm 系統設定 (41表) - 幣別、港口、報表格式
- [x] tnm/tjm/tpm/trm 其他 (10表) - 歷史、索賠、拋轉、分析

---

## Quick Reference

### 已驗證的連動關係
```
[[tfm01.fa01]] (訂單)
  -> [[tfm02.fb01]]
  -> [[tfm03.fc01]]
  -> [[tfm05.fe01]]
  -> [[tgm01.ga2301]] (採購連回訂單)
  -> [[tgm02.gb2601]] (採購明細連回訂單)
  -> [[tem05.ee011]] (訂單BOM)

[[thm01]] (出貨) 自動觸發 [[tlm01]] (應收帳款)
[[tgm01]] (採購) 自動觸發 [[tlm09]] (應付帳款)
```

### BOM 計算公式
```
採購數量 = 訂購數量 * (ee04 / ee05)
```

---

## Quick Reference

### 已確認的表
| 表名 | 用途 | 主鍵 |
|------|------|------|
| tdm01 | 產品基本資料 | da01 |
| tdm02 | 產品子描述 | (db01, db02) |
| tdm05 | 產品BOM | (de01, de02) |
| tcm01 | 供應商基本資料 | ca01 |
| tcm05 | 供應商產品 | (ce010, ce011, ce02, ce04) |
| tem01 | 報價單主檔 | ea01 |
| tem02 | 報價單明細 | (eb01, eb02) |
| tem05 | 報價BOM | (ee010, ee011, ee02, ee03) |
| tfm01 | 訂單主檔 | fa01 |
| tfm02 | 訂單明細 | (fb01, fb02) |

### 待確認的表 (推測)
| 表名 | 推測用途 |
|------|----------|
| tfm03 | 產品出貨排程 |
| tfm04 | 訂單出貨排程 |
| tfm05 | 訂單選採購 |
| tpm01 | 採購單主檔 |
| tpm02 | 採購單明細 |
| tsm01 | 出貨單主檔 |
| tsm02 | 出貨單明細 |

### 查詢起點
```python
# 使用現有腳本查詢新表
python sql/query_trade_schema.py
```
