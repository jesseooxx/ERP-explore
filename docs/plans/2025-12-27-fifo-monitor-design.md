# FIFO 訂單監控系統設計

> 設計日期：2025-12-27
> 狀態：已確認，待實作

## 問題描述

客戶對同一產品會下多張 Blank Order（可分批回扣的訂單）。依 FIFO 原則，應先消完最早的訂單才能扣下一張。但實務上可能因時間久遠或人為疏忽，導致跳過舊訂單直接扣到新訂單。

**需求：** 當操作人員在 ERP 系統新增排程時，自動檢查是否有更早的訂單未消完，若有則彈窗警告。

## 系統架構

```
┌─────────────────────────────────────────────────────────┐
│                    FIFO 監控服務                         │
│                  (Python 背景程式)                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   ┌──────────────┐      ┌──────────────┐               │
│   │  SQL 監控器   │ ──→  │  FIFO 檢查器  │               │
│   │  (每 3 秒輪詢) │      │              │               │
│   └──────────────┘      └──────┬───────┘               │
│                                │                        │
│                                ▼                        │
│                        ┌──────────────┐                │
│                        │  警告彈窗     │                │
│                        │  (Windows)   │                │
│                        └──────────────┘                │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   SQL Server        │
              │   (DATAWIN 資料庫)   │
              └─────────────────────┘
```

### 運作環境

- **監控程式位置：** 本地電腦（操作人員的工作機）
- **資料庫位置：** 公司伺服器（遠端 SQL Server）
- **連線方式：** pyodbc + ODBC Driver 17

## 資料庫結構

### 相關資料表

| 資料表 | 用途 | 關鍵欄位 |
|--------|------|----------|
| tfm01 | 訂單主檔 | fa01(PI編號), fa03(訂單日期), fa04(客戶) |
| tfm02 | 訂單明細 | fb01(PI編號), fb03(產品), fb09(訂單數量) |
| tfm03 | 出貨排程 | fc01(PI編號), fc04(產品), fc05(排程數量), fc06(已出貨), fc10(客戶) |

### Blank Order 運作邏輯

1. 客戶下單 → 建立 tfm01 + tfm02（訂單總數量）
2. 客戶第一次回扣 → 新增 tfm03（排程記錄）
3. 客戶第二次回扣 → 再新增 tfm03（另一筆排程）
4. 重複直到訂單消完

### 剩餘數量計算

```sql
-- 單張訂單的剩餘數量
SELECT
    t1.fa01,
    t2.fb09 as 訂單數量,
    SUM(t3.fc06) as 已出貨,
    (t2.fb09 - ISNULL(SUM(t3.fc06), 0)) as 剩餘數量
FROM tfm01 t1
INNER JOIN tfm02 t2 ON t2.fb01 = t1.fa01
LEFT JOIN tfm03 t3 ON t3.fc01 = t1.fa01 AND t3.fc04 = t2.fb03
WHERE t1.fa01 = @PI AND t2.fb03 = @Product
GROUP BY t1.fa01, t2.fb09
```

## 監控與觸發邏輯

### 監控機制

```
每 3 秒輪詢 tfm03 表格
        ↓
比對記錄數是否增加
        ↓
偵測到新排程記錄
        ↓
觸發 FIFO 檢查
```

### FIFO 檢查流程

```
輸入：新排程的 [PI編號] + [產品代碼] + [客戶代碼]
                    ↓
Step 1: 查出這張 PI 的訂單日期
                    ↓
Step 2: 查同客戶+同產品，是否有「更早的訂單」還有剩餘
        WHERE 客戶 = ? AND 產品 = ?
          AND 訂單日期 < 當前PI的訂單日期
          AND 剩餘數量 > 0
                    ↓
Step 3: 有更早的未消完訂單？
        → 是：彈出警告視窗
        → 否：不做任何動作
```

## 警告視窗設計

```
┌─────────────────────────────────────────────────────────────┐
│  ⚠️  FIFO 訂單警告                                     [X] │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  您正在處理的訂單：                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  PI: I16C13    日期: 2016/12/14    產品: 0965281   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ⚠️ 以下訂單還有剩餘數量，依 FIFO 應優先處理：             │
│                                                             │
│  ┌───────────┬────────────┬──────────┬───────────┐        │
│  │ PI 編號   │ 訂單日期   │ 剩餘數量 │ 已過時間   │        │
│  ├───────────┼────────────┼──────────┼───────────┤        │
│  │ 56170     │ 2011/08/05 │   2,027  │ 5年4個月  │        │
│  │ I13714    │ 2013/07/30 │      20  │ 3年5個月  │        │
│  │ I14605    │ 2014/06/16 │      54  │ 2年6個月  │        │
│  └───────────┴────────────┴──────────┴───────────┘        │
│                                                             │
│              [ 我知道了 ]     [ 複製清單 ]                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 時間顯示規則

- 超過 1 年 → 顯示「X年Y個月」
- 不到 1 年 → 顯示「X個月」
- 不到 1 個月 → 顯示「X天」

### 按鈕功能

| 按鈕 | 功能 |
|------|------|
| 我知道了 | 關閉視窗，繼續作業 |
| 複製清單 | 將異常清單複製到剪貼簿 |

## 安全設計

### 第 1 層：資料庫權限（最小權限原則）

```sql
-- 建立專用唯讀帳號
CREATE LOGIN fifo_monitor WITH PASSWORD = '強密碼';
CREATE USER fifo_monitor FOR LOGIN fifo_monitor;

-- 只給必要的 SELECT 權限
GRANT SELECT ON dbo.tfm01 TO fifo_monitor;
GRANT SELECT ON dbo.tfm02 TO fifo_monitor;
GRANT SELECT ON dbo.tfm03 TO fifo_monitor;

-- 明確拒絕所有寫入權限
DENY INSERT, UPDATE, DELETE, ALTER, EXECUTE ON SCHEMA::dbo TO fifo_monitor;
```

### 第 2 層：連線層級唯讀

```python
conn = pyodbc.connect(
    "...;"
    "ApplicationIntent=ReadOnly;"
)
```

### 第 3 層：安全查詢包裝器

```python
class SafeQueryExecutor:
    FORBIDDEN_KEYWORDS = [
        'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER',
        'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE', 'MERGE'
    ]

    def execute(self, query, params=None):
        # 檢查必須以 SELECT 開頭
        if not query.strip().upper().startswith('SELECT'):
            raise SecurityError("禁止執行非 SELECT 語句")

        # 檢查不能包含危險關鍵字
        for keyword in self.FORBIDDEN_KEYWORDS:
            if re.search(r'\b' + keyword + r'\b', query.upper()):
                raise SecurityError(f"禁止使用 {keyword}")

        # 檢查不能有多重語句
        if ';' in query:
            raise SecurityError("禁止多重語句")

        return self.cursor.execute(query, params)
```

### 第 4 層：白名單查詢

所有允許執行的查詢都預先定義在 `FIFOQueries` 類別中，程式只能執行這些預定義的查詢。

## 資源消耗預估

| 資源 | 消耗 |
|------|------|
| CPU | < 1%（每 3 秒一次簡單查詢）|
| 記憶體 | 約 30-50 MB |
| 網路 | 每次查詢約 1-2 KB |
| SQL Server 負擔 | 極小 |

## 實作規劃

### 檔案結構

```
fifo_monitor/
├── main.py              # 主程式入口
├── monitor.py           # SQL 監控器
├── checker.py           # FIFO 檢查邏輯
├── alert.py             # 警告視窗 (tkinter)
├── queries.py           # SQL 查詢白名單
├── security.py          # 安全查詢執行器
└── config.py            # 設定檔
```

### 相依套件

- pyodbc：SQL Server 連線
- tkinter：警告視窗（Python 內建）

## 後續擴充可能

1. **記錄功能：** 將每次警告記錄到 log 檔
2. **報表功能：** 定期產出 FIFO 異常報表
3. **即時模式：** 研究更即時的觸發方式（如 SQL Change Tracking）
