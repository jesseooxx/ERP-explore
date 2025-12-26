# Trade Module Flow Mapping - Context

## Last Updated: 2025-12-26

## Current State

### Completed Work
產品主檔 (tdm 系列) 的 SQL 欄位對應已完成驗證:
- **tdm01**: 產品基本資料 (85欄位) - da01~da84
- **tdm02**: 產品子描述 (4欄位) - db01~db04
- **tdm05**: 產品BOM組合 (19欄位) - de01~de19
- **tdm09**: 產品售價等級 (16欄位) - di01~di15
- **tcm01**: 供應商基本資料 (45欄位) - ca01~ca45
- **tcm05**: 供應商產品關係 (25欄位) - ce010~ce24
- **tem01**: 報價單主檔 (53欄位) - ea01~ea49
- **tem02**: 報價單明細 (47欄位) - eb01~eb45
- **tem05**: 報價BOM (20欄位) - ee010~ee19
- **tfm01**: 訂單主檔 (99欄位) - fa01~fa86
- **tfm02**: 訂單明細 (67欄位) - fb01~fb67

### 驗證完成的關鍵欄位對應
參見: `docs/產品主檔欄位對照表.md`

### 已建立的查詢腳本
- `sql/query_trade_schema.py` - 查詢所有貿易表結構
- `sql/query_product_detail.py` - 查詢產品明細
- `sql/query_tfm_structure.py` - 查詢訂單表結構
- `sql/verify_284102.py` - 驗證 284102 產品資料

---

## Next Task: 完整貿易流程編號對應

### 需要研究的流程
```
報價 (Quotation) -> 訂單 S/C (Sales Contract/PI)
                          |
                          v
                    訂單轉需求作業
                          |
                          v
                    出口採購作業 (P/O)
                          |
                          v
                    船務出口出貨作業 (Shipping)
```

### 需要找出的資料表
1. **訂單轉需求**: 可能是 tfm03, tfm04, tfm05 或其他表
2. **採購單**: 可能是 tpm 系列 (Purchase Order)
3. **出貨單**: 可能是 tsm 系列 (Shipping)

### 需要建立的關聯圖
- 單據編號之間的連動關係
- 欄位之間的 FK 關係
- 狀態流轉圖

---

## Database Connection Info
- Server: localhost
- Database: DATAWIN
- Auth: Windows Authentication
- Data: 2017年備份 (本地開發環境)

---

## Key Discoveries This Session

### 1. 表名規則
- **tdm**: 產品主檔 (Item Data Master)
- **tcm**: 供應商主檔 (Supplier/Customer Master)
- **tem**: 報價單 (Quotation)
- **tfm**: 訂單 (Sales Contract)
- 推測: **tpm** = 採購, **tsm** = 出貨

### 2. 欄位命名規則
- 第一碼 = 表代碼 (d=item, c=customer, e=quotation, f=order)
- 第二碼 = 子表序號 (01=主檔, 02=明細, 05=BOM)
- 後續 = 欄位序號

### 3. 日期格式
- 統一使用 varchar(8) 格式 YYYYMMDD

### 4. 主鍵規則
- 主檔: 單一欄位 (如 da01, fa01)
- 明細: 複合主鍵 (如 fb01+fb02)

---

## Files Modified This Session
- `docs/產品主檔欄位對照表.md` - 完整重寫
- `docs/284102_產品編號關係分析.md` - 修正欄位對應

## Commits
- `ff7f0b6` - Add verified SQL field mappings for trade module tables

---

## Next Steps for New Session

1. **查詢所有 t*m 系列表**
   ```sql
   SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
   WHERE TABLE_NAME LIKE 't_m%' ORDER BY TABLE_NAME
   ```

2. **識別採購相關表 (tpm 系列)**
   - 查詢結構
   - 找出與 tfm 的關聯欄位

3. **識別出貨相關表 (tsm 系列)**
   - 查詢結構
   - 找出與 tfm, tpm 的關聯欄位

4. **建立完整流程圖**
   - 使用 Mermaid 語法
   - 標註所有編號連動關係

5. **驗證編號連動**
   - 從一筆訂單追蹤到採購單
   - 從採購單追蹤到出貨單
