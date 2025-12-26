# Trade Module Flow Mapping - Context

## Last Updated: 2025-12-26

## Current State: Phase 6 - COMPLETE

### All Research COMPLETED

已完成所有 T 模組表格研究，包含：
- 主流程: tem -> tfm -> tgm -> thm
- 輔助模組: tlm, tqm, tmm, trm, tjm, tpm, tnm
- 設定模組: tam, tsm
- 主檔: tbm, tcm, tdm

### 文檔建立進度 - ALL DONE

```
docs/trade-module/
  _index.yaml        [DONE] - 模組索引和欄位映射
  _auxiliary.md      [DONE] - 輔助模組彙整 (tlm, tqm, tmm, etc.)
  00-overview.md     [DONE] - 主流程總覽
  01-tam.md          [DONE] - 系統設定
  02-tsm.md          [DONE] - 運作參數
  03-tbm.md          [DONE] - 客戶主檔
  04-tcm.md          [DONE] - 供應商主檔
  05-tdm.md          [DONE] - 產品主檔
  06-tem.md          [DONE] - 報價模組
  07-tfm.md          [DONE] - 訂單模組
  08-tgm.md          [DONE] - 採購模組
  09-thm.md          [DONE] - 出貨/INV/PKG
```

---

## Key Discoveries (Verified)

### 1. 核心連動欄位
```
[[tfm01.fa01]] (訂單編號)
  -> [[tgm01.ga2301]] (採購單連回訂單)
  -> [[tgm02.gb2601]] (採購明細連回訂單)
  -> [[tem05.ee011]] (訂單BOM識別碼)
```

### 2. 主鍵彙整
| 模組 | 表 | 主鍵 |
|------|-----|------|
| tbm | tbm01 | ba01 |
| tcm | tcm01 | ca01 |
| tdm | tdm01 | da01 |
| tem | tem01 | ea01 |
| tfm | tfm01 | fa01 |
| tgm | tgm01 | ga01 |
| thm | thm01 | ha01 |

### 3. BOM 計算
```
採購數量 = 訂購數量 * (ee04 / ee05)
         = [[tfm02.fb09]] * ([[tem05.ee04]] / [[tem05.ee05]])
```

### 4. 自動觸發
- [[thm01]] 存檔 -> 自動建立 [[tlm01]] (應收帳款)
- [[tgm01]] 存檔 -> 自動建立 [[tlm09]] (應付帳款)

---

## 文檔使用的標記格式

使用 `[[table.field]]` 格式進行跨模組引用：
- `[[tfm01]]` = 引用 tfm01 表
- `[[tfm01.fa01]]` = 引用 tfm01 的 fa01 欄位
- `[[tfm01.fa01]] -> [[tgm01.ga2301]]` = FK 關係

---

## Status

All documentation complete. Ready for git commit.

---

## Database Connection Info
- Server: localhost
- Database: DATAWIN
- Auth: Windows Authentication
- Data: 2017年備份
