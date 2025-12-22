# DataWin ERP SQL 資料庫結構詳細說明

## 1. 資料庫概覽

### 1.1 SQL 腳本統計

| 類型 | 數量 | 每檔大小 | 總行數 | 說明 |
|-----|------|---------|-------|------|
| **proc.sql** | 9 版本 | ~39 MB | ~798,000 行 | 存儲程序與函數 |
| **trigger.sql** | 9 版本 | ~1.8 MB | ~58,800 行 | 觸發器 |
| **view.sql** | 9 版本 | ~150 KB | ~145,000 行 | 檢視表 |
| **create_table_*.sql** | 17 個 | 各異 | - | 建表腳本 |
| **add_column_*.sql** | 20+ 個 | 各異 | - | 欄位擴充 |
| **總計** | 62 個 | ~330 MB | ~860,000 行 | - |

### 1.2 版本目錄結構

```
X:\source\
├── sn20010201~sn20011001/     (2020/01/02 ~ 01/10)
│   └── script/
│       ├── 20200102/1/        (增量腳本)
│       ├── 20200103/1/        (增量腳本)
│       └── 20200110/2/        (完整快照: proc.sql, trigger.sql, view.sql)
│
├── sn20011401~sn20012001/     (2020/01/14 ~ 01/20)
├── sn20020701/                (2020/02/07)
├── SN20021101_SN20022001/     (2020/02/11 ~ 02/20)
├── sn20022101~sn20022801/     (2020/02/21 ~ 02/28)
├── sn20030101~sn20031001/     (2020/03/01 ~ 03/10)
├── sn20031101~sn20032001/     (2020/03/11 ~ 03/19)
├── sn20032301~sn20033101/     (2020/03/23 ~ 03/31)
└── sn20040201~sn20041001/     (2020/04/02 ~ 04/10)
```

---

## 2. 資料庫物件統計

### 2.1 存儲程序與函數 (~2,952 個)

| 類別 | 前綴 | 數量 | 功能描述 |
|------|-----|------|---------|
| 計算函數 | Calculate_* | 多個 | 成本計算、庫存計算 |
| 資料查詢 | DLL_* | 多個 | 資料查詢、裝配、庫存管理 |
| 工具函數 | fn_* | 50+ | 日期處理、格式轉換、計算 |
| MRP 函數 | fn_MRP_* | 30+ | 物料需求計劃 |
| 會計函數 | fn_ACCT_* | 多個 | 會計相關計算 |
| 存儲程序 | sp_* | 多個 | 業務流程處理 |

### 2.2 觸發器 (~50+ 個)

| 類型 | 功能 |
|------|------|
| UPDATE 觸發器 | 資料更新監控、自動計算 |
| DELETE 觸發器 | 刪除審計、關聯資料處理 |
| INSERT 觸發器 | 新增資料驗證、自動編號 |

### 2.3 檢視表 (~30+ 個)

| 檢視表名稱 | 功能 |
|-----------|------|
| JIESHIDE_RETURN_VIEW | 結石德退貨檢視 |
| PUTAI_RETURN_VIEW | 普泰退貨檢視 |
| VCustomer | 客戶主檔檢視 |
| V_Trade_Stock_* | 貿易庫存相關檢視 |

---

## 3. 資料表命名規則

### 3.1 資料表前綴對照

| 前綴 | 模組 | 英文名稱 | 說明 |
|------|------|---------|------|
| tf | 貿易/運輸 | Trade/Transport | 運輸排程、出貨 |
| tq | 報價/詢價 | Quotation | 報價單管理 |
| pq | 採購品質 | Purchase Quality | 採購品質檢驗 |
| kq | 庫存查詢 | Inventory Query | 庫存相關設定 |
| pb | 採購基本 | Purchase Base | 採購基礎資料 |
| kh | 客戶 | Customer | 客戶資料 |
| ks | 庫存 | Stock | 庫存管理 |
| kt | 生產排程 | Production | 生產製造 |
| pc | 採購合約 | Purchase Contract | 採購合約 |
| td | 交易明細 | Transaction Detail | 交易細節 |
| qo | 報價訂單 | Quote Order | 報價訂單 |
| ku | 庫存單位 | Stock Unit | 庫存單位設定 |
| ts | 系統參數 | System | 系統設定 |
| te | 工作狀態 | Task/Event | 工作追蹤 |

### 3.2 資料表後綴規則

| 後綴 | 說明 | 範例 |
|------|------|------|
| m01 | 主表 (Master) | tfm01 (運輸主檔) |
| m02 | 明細表 (Detail) | tfm02 (運輸明細) |
| m03 | 排程表 (Schedule) | tfm03 (排程明細) |
| m04 | 彙總表 (Summary) | tfm04 (排程彙總) |

### 3.3 欄位命名規則

| 規則 | 說明 | 範例 |
|------|------|------|
| X##格式 | 前綴+兩位數字 | qa01, qa02, qa03... |
| 01 = 主鍵 | 第一個欄位通常是主鍵 | fa01 (S/C 編號) |
| 02-09 | 基本屬性 | fa02 (日期), fa04 (客戶) |
| 10+ | 擴充屬性 | fa10, fa11... |

---

## 4. 核心資料表結構

### 4.1 運輸模組 (tf*)

#### tfm01 - 運輸主檔 (Sales Contract Master)
```sql
-- 主要欄位
fa01   VARCHAR(10)   -- S/C 編號 (主鍵)
fa02   VARCHAR(8)    -- 日期
fa04   VARCHAR(10)   -- 客戶編號
fa08   VARCHAR(20)   -- 客戶訂單號
```

#### tfm02 - 運輸明細 (Sales Contract Detail)
```sql
-- 主要欄位
fb01   VARCHAR(10)   -- S/C 編號 (外鍵)
fb03   VARCHAR(20)   -- 品項編號
fb09   FLOAT         -- 數量
fb23   FLOAT         -- 外箱裝數量
fb25   FLOAT         -- 外箱材積
fb26   VARCHAR(10)   -- 材積單位 (CBM/CU'FT)
```

#### tfm03 - 排程明細 (Schedule Detail)
```sql
-- 主要欄位
fc01   VARCHAR(10)   -- S/C 編號
fc02   VARCHAR(8)    -- E.T.D. (預計出貨日)
fc031  VARCHAR(20)   -- 目的地
fc04   VARCHAR(20)   -- 品項編號
fc05   FLOAT         -- 排程數量
fc06   FLOAT         -- 已出貨數量
fc08   VARCHAR(1)    -- 完成標記 (Y/N)
```

#### tfm04 - 排程彙總 (Schedule Summary)
```sql
-- 主要欄位
fd01   VARCHAR(10)   -- S/C 編號
fd02   VARCHAR(8)    -- E.T.D.
fd03   VARCHAR(20)   -- 目的地
fd06   FLOAT         -- 總材積
fd07   FLOAT         -- 總重量
fd08   FLOAT         -- 總金額
```

### 4.2 系統參數表 (ts*)

#### tsm01 - 系統參數設定
```sql
-- 主要欄位
sa01   VARCHAR(10)   -- 參數代碼 (主鍵)
sa03   VARCHAR(100)  -- 參數值
sa04   FLOAT         -- 數值參數

-- 常用參數代碼
IC15   -- CBM/CUFT 換算率 (預設 35.315)
Q079   -- dept#/store# 預設設定
Q434   -- Chain Store 設定
Q882   -- 預設天數設定
F010   -- 預設天數 (30)
F999   -- Chain Store 功能開關
```

### 4.3 採購品質模組 (pq*)

#### pqm206 - 保險類型設定
```sql
CREATE TABLE pqm206 (
    pqgx01   VARCHAR(10)   NOT NULL,  -- 保險類型代碼 (主鍵)
    pqgx02   VARCHAR(50)   NOT NULL   -- 保險類型名稱
)
```

#### pqm207 - 保險擔保類型
```sql
CREATE TABLE pqm207 (
    pqgy01   VARCHAR(10)   NOT NULL,  -- 類型1 (主鍵)
    pqgy02   VARCHAR(10)   NOT NULL,  -- 類型2 (主鍵)
    pqgy03   VARCHAR(50)   NOT NULL   -- 說明
)
```

#### pqm208 - 採購品質檢驗主記錄
```sql
CREATE TABLE pqm208 (
    pqgz01   INT IDENTITY  NOT NULL,  -- 自動編號 (主鍵)
    pqgz02   VARCHAR(20)   NOT NULL,  -- PO 號
    pqgz03   INT           NOT NULL,  -- 序號
    pqgz04   VARCHAR(20)   NOT NULL,  -- 供應商
    pqgz05   VARCHAR(50)   NOT NULL,  -- 採購件號
    pqgz06   FLOAT         NOT NULL,  -- 品質指標1
    pqgz07   FLOAT         NOT NULL,  -- 品質指標2
    -- ... 更多品質指標
)
```

### 4.4 庫存查詢模組 (kq*)

#### 客戶定制表範例

**zhonggui_kqm01** - 中規供應商配置
```sql
CREATE TABLE zhonggui_kqm01 (
    qa01   VARCHAR(1)    NOT NULL,   -- 類型
    qa02   VARCHAR(6)    NOT NULL,   -- 代碼
    qa03   FLOAT         NOT NULL,   -- 數值1
    qa04   FLOAT         NOT NULL,   -- 數值2
    qa05   FLOAT         NOT NULL,   -- 數值3
    qa06   VARCHAR(1)    NOT NULL,   -- 標記
    CONSTRAINT PK_zhonggui_kqm01 PRIMARY KEY (qa01, qa02)
)
```

**wangpin_kqm02** - 旺品商品認證
```sql
CREATE TABLE wangpin_kqm02 (
    qb01   VARCHAR(10)   NOT NULL,   -- 分類代碼1
    qb02   VARCHAR(10)   NOT NULL,   -- 分類代碼2
    qb03   VARCHAR(20)   NOT NULL,   -- 項目編號
    qb04   VARCHAR(10)   NOT NULL,   -- 認證類型
    -- ... 更多配置欄位
    CONSTRAINT PK_wangpin_kqm02 PRIMARY KEY (qb01, qb02, qb03, qb04)
)
```

### 4.5 POS 整合模組

#### qiyi_pos_master - 奇異 POS 主單據
```sql
CREATE TABLE qiyi_pos_master (
    out_date    VARCHAR(8)    NOT NULL,  -- 輸出日期
    out_time    VARCHAR(6)    NOT NULL,  -- 輸出時間
    pda_no      VARCHAR(20)   NOT NULL,  -- PDA 編號
    doc_type    VARCHAR(10)   NOT NULL,  -- 單據類型
    doc_date    VARCHAR(8)    NOT NULL,  -- 單據日期
    doc_comp    VARCHAR(20)   NOT NULL,  -- 公司代碼
    doc_ware    VARCHAR(20)   NOT NULL,  -- 倉庫代碼
    doc_object  VARCHAR(50)   NOT NULL,  -- 對象
    doc_no      VARCHAR(30)   NOT NULL,  -- 單據編號
    count_num   INT           NOT NULL,  -- 計數
    trans_num   INT           NOT NULL,  -- 傳輸編號
    CONSTRAINT PK_qiyi_pos_master
        PRIMARY KEY (out_date, out_time, pda_no, doc_type)
)
```

#### qiyi_pos_detail - 奇異 POS 明細
```sql
CREATE TABLE qiyi_pos_detail (
    out_date    VARCHAR(8)    NOT NULL,
    out_time    VARCHAR(6)    NOT NULL,
    pda_no      VARCHAR(20)   NOT NULL,
    doc_type    VARCHAR(10)   NOT NULL,
    origno      VARCHAR(30)   NOT NULL,  -- 原始編號
    itemno      VARCHAR(50)   NOT NULL,  -- 品項編號
    lotno       VARCHAR(30)   NOT NULL,  -- 批號
    label       VARCHAR(50)   NOT NULL,  -- 標籤
    itemqty     FLOAT         NOT NULL,  -- 數量
    itemunit    VARCHAR(10)   NOT NULL,  -- 單位
    CONSTRAINT PK_qiyi_pos_detail
        PRIMARY KEY (out_date, out_time, pda_no, doc_type,
                     origno, itemno, lotno, label)
)
```

### 4.6 EDI 整合

#### poreply_edi - 供應商 EDI 回覆
```sql
CREATE TABLE poreply_edi (
    SN              INT IDENTITY  NOT NULL,  -- 序號 (主鍵)
    PoNo            VARCHAR(30)   NOT NULL,  -- PO 號
    Seq             INT           NOT NULL,  -- 序號
    ReplyItemNo     VARCHAR(50)   NULL,      -- 回覆品號
    ReplyItemName   VARCHAR(100)  NULL,      -- 回覆品名
    ReplyQty        FLOAT         NULL,      -- 回覆數量
    ReplyETD        VARCHAR(8)    NULL,      -- 回覆交期
    ReplyLatestDate VARCHAR(8)    NULL,      -- 最新回覆日期
    Remark          VARCHAR(500)  NULL,      -- 備註
    TraceHistory    TEXT          NULL       -- 追蹤歷史
)
```

---

## 5. 核心存儲程序分析

### 5.1 sp_tfm_schedule_tq8i20 - S/C 自動排程

**功能**：根據 Sales Contract 自動計算出貨排程

**參數**：
```sql
@SCNo   VARCHAR(10)         -- S/C 編號
@fd02   VARCHAR(8)          -- E.T.D. (預計出貨日)
@fd031  VARCHAR(20)         -- 目的地
@auto   VARCHAR(1) = 'Y'    -- 自動排程='Y', 手動='N'
@size   NUMERIC(20,6) = 0   -- 貨櫃尺寸限制
```

**處理流程**：
```
1. 驗證 S/C 編號
   ↓
2. 取得系統參數
   - IC15: CBM/CUFT 換算率 (預設 35.315)
   - Q882: 預設天數設定
   - F010: 預設天數 (30)
   ↓
3. 計算已排程材積
   - 從 tfm03 讀取現有排程
   - 計算剩餘貨櫃空間
   ↓
4. 建立暫存表 #TB
   - 彙總 tfm02 待排程數量
   - 減去 tfm03 已排程數量
   ↓
5. 迴圈處理每個品項
   - 計算材積 = 數量 × 外箱材積 / 外箱裝數
   - 根據貨櫃限制分配數量
   - 新增或更新 tfm03 排程
   ↓
6. 更新排程彙總 (tfm04)
   ↓
7. 更新完成狀態 (tem08)
```

**關鍵 SQL 片段**：
```sql
-- 材積計算 (CBM/CUFT 轉換)
SELECT @IC15 = dbo.GetSa04FromTsm01('IC15', 1, 35.315)

-- 計算需要材積
SELECT @NEED_SIZE = ISNULL(@sche_qty * @fb25 * @trans2 / @fb23, 0)

-- 根據貨櫃限制分配
IF (@CON_SIZE > @NEED_SIZE)
    SELECT @CON_SIZE = @CON_SIZE - @NEED_SIZE
ELSE
    SELECT @sche_qty = FLOOR(@CON_SIZE / @fb25 / @trans2) * @fb23
```

---

## 6. 資料關聯圖

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   tsm01     │     │   khm*      │     │   pbm*      │
│  (系統參數)  │     │   (客戶)    │     │   (採購)    │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐
                    │   tfm01     │────▶│   pqm208    │
                    │ (S/C 主檔)  │     │ (品質檢驗)  │
                    └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   tfm02     │
                    │ (S/C 明細)  │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐           ┌─────────────┐
       │   tfm03     │           │   tfm04     │
       │ (排程明細)   │──────────▶│ (排程彙總)   │
       └─────────────┘           └─────────────┘
              │
              ▼
       ┌─────────────┐
       │   tem08     │
       │ (工作狀態)   │
       └─────────────┘
```

---

## 7. 預設值與約束

### 7.1 常用預設值

```sql
-- 數值預設為 0
EXEC sp_bindefault 'dbo.FLOATZERO', 'table.column'

-- 字串預設為空
EXEC sp_bindefault 'dbo.VCHAREMPTY', 'table.column'
```

### 7.2 欄位修改範例

```sql
-- 新增欄位
ALTER TABLE [dbo].[XiangQuan_tqm01] WITH NOCHECK ADD
    qa11 FLOAT NULL  /* 計數次數 */

-- 更新現有資料
UPDATE dbo.XiangQuan_tqm01 SET qa11 = ISNULL(qa11, 0)

-- 改為 NOT NULL
ALTER TABLE [dbo].[XiangQuan_tqm01]
    ALTER COLUMN [qa11] FLOAT NOT NULL

-- 綁定預設值
EXEC sp_bindefault N'[dbo].[FLOATZERO]', N'[XiangQuan_tqm01].[qa11]'
```

---

## 8. 常用系統參數 (tsm01)

| 參數代碼 | 說明 | 預設值 |
|---------|------|-------|
| IC15 | CBM/CUFT 換算率 | 35.315 |
| Q079 | dept#/store# 預設設定 | NN |
| Q434 | Chain Store 設定 | NNNN |
| Q882 | 預設天數設定 | - |
| F010 | 預設天數 | 30 |
| F999 | Chain Store 功能開關 | NNN |

---

## 附錄 A：SQL 檔案清單

| 檔案路徑 | 大小 | 說明 |
|---------|------|------|
| sp_tfm_schedule_tq8i20.sql | 20 KB | 排程存儲程序 |
| sn*/script/*/proc.sql | ~39 MB | 所有存儲程序 |
| sn*/script/*/trigger.sql | ~1.8 MB | 所有觸發器 |
| sn*/script/*/view.sql | ~150 KB | 所有檢視表 |
| create_table_*.sql | 各異 | 建表腳本 |
| add_column_*.sql | 各異 | 欄位擴充 |

## 附錄 B：客戶定制表清單

| 客戶 | 資料表 | 用途 |
|------|-------|------|
| 旺品 | wangpin_kqm02 | 商品認證 |
| 旺品 | wangpin_kqm03 | 認證路由 |
| 旺品 | wangpin_kqm04 | 年月設定 |
| 旺品 | wangpin_kqm05 | 擴充設定 |
| 旺品 | wangpin_kqm06 | 擴充設定 |
| 中規 | zhonggui_kqm01 | 供應商設定 |
| 中規 | zhonggui_kqm02 | 擴充設定 |
| 裝盟 | zhuangmeng_kqm01 | 供應商設定 |
| 食恆 | shiheng_kqm03 | 供應商設定 |
| 奇異 | qiyi_pos_master | POS 主檔 |
| 奇異 | qiyi_pos_detail | POS 明細 |
| 德保清 | DeBaoQing_tqm01 | 擔保設定 |
