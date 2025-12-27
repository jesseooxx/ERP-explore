# FIFO 訂單監控系統

背景監控程式，當 ERP 系統新增排程時自動檢查 FIFO 違規並彈窗警告。

## 功能

- 每 3 秒輪詢 SQL Server 的 `tfm03` 表格
- **客戶過濾**：可設定只監控特定客戶的訂單（避免看到其他人的操作）
- 偵測到新排程時，查詢同客戶+同產品是否有更早的訂單未消完
- 若有違規則顯示 Windows 彈窗警告
- 支援複製違規清單到剪貼簿

## 需求

- Python 3.x
- pyodbc
- tkinter（Python 內建）
- ODBC Driver 17 for SQL Server

## 安裝

```bash
pip install pyodbc
```

## 使用方式

### 開發模式（本地資料庫）

```bash
python -m fifo_monitor.main
```

### Demo 模式（不需資料庫）

```bash
python -m fifo_monitor.demo
```

---

## 部署到公司伺服器

### 步驟 1：確認公司 SQL Server 資訊

需要知道：
- **伺服器位址**：IP 或主機名稱（例如 `192.168.1.100` 或 `COMPANY-SQL`）
- **驗證方式**：Windows 驗證（網域帳號）或 SQL 驗證（帳號密碼）

查詢方式：
- 問 IT 或 DBA
- 查看 ERP 軟體的設定檔（通常在 X:\EXE\ 或 X:\Config\）
- 查看公司電腦的 ODBC 資料來源設定

### 步驟 2：在公司電腦安裝 Python 環境

```bash
# 1. 安裝 Python 3.x
#    下載: https://www.python.org/downloads/

# 2. 安裝依賴
pip install pyodbc python-dotenv

# 3. 確認 ODBC 驅動
#    下載: https://go.microsoft.com/fwlink/?linkid=2249004
```

### 步驟 3：測試連線

```bash
# Windows 驗證（用網域帳號）
python -m fifo_monitor.test_connection --server 192.168.1.100

# SQL 驗證（用帳號密碼）
python -m fifo_monitor.test_connection --server 192.168.1.100 --auth sql --user myuser --password mypass
```

成功輸出：
```
✓ 連線成功!
✓ tfm01: 12,345 筆資料
✓ tfm03: 23,456 筆資料
✓ 所有測試通過！可以啟動 FIFO 監控
```

### 步驟 4：設定環境變數

**方法 A：使用 .env 檔案（推薦）**

```bash
# 複製範例檔案
copy fifo_monitor\.env.example fifo_monitor\.env

# 編輯 .env，填入正確的值
FIFO_DB_SERVER=192.168.1.100
FIFO_DB_NAME=DATAWIN
FIFO_AUTH_MODE=windows
```

**方法 B：使用系統環境變數**

```cmd
set FIFO_DB_SERVER=192.168.1.100
set FIFO_DB_NAME=DATAWIN
set FIFO_AUTH_MODE=windows
```

### 步驟 5：啟動監控

```bash
python -m fifo_monitor.main_production
```

### 步驟 6：設為開機自動執行（可選）

**方法 A：工作排程器**

1. 開啟「工作排程器」
2. 建立基本工作
3. 觸發程序：登入時
4. 動作：啟動程式
   - 程式：`python`
   - 引數：`-m fifo_monitor.main_production`
   - 開始位置：`C:\path\to\ERP-explore`

**方法 B：放入啟動資料夾**

建立 `start_fifo_monitor.bat`：
```batch
@echo off
cd /d C:\path\to\ERP-explore
set FIFO_DB_SERVER=192.168.1.100
python -m fifo_monitor.main_production
```

複製到 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

---

### 測試觸發監控

```bash
# 先啟動監控
python -m fifo_monitor.main

# 另開終端執行測試（會插入並刪除測試資料）
python -m fifo_monitor.test_trigger
```

## 檔案結構

```
fifo_monitor/
├── __init__.py           # 套件初始化
├── config.py             # 開發環境設定（本地 SQL Server）
├── config_production.py  # 生產環境設定（公司 SQL Server）
├── .env.example          # 環境變數範例檔
├── security.py           # SQL 安全驗證（只允許 SELECT）
├── queries.py            # SQL 查詢白名單
├── utils.py              # 時間格式化工具
├── checker.py            # FIFO 違規檢查邏輯
├── monitor.py            # tfm03 新增記錄偵測
├── alert.py              # tkinter 警告視窗
├── main.py               # 開發模式入口（本地）
├── main_production.py    # 生產模式入口（公司）
├── test_connection.py    # 連線測試工具
├── demo.py               # Demo 模式入口
├── test_insert.py        # 測試：查詢現有資料
└── test_trigger.py       # 測試：插入資料觸發監控
```

## 運作原理

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  TFM03Monitor│────▶│ FIFOChecker │────▶│ AlertWindow │
│  (偵測新排程) │     │ (檢查違規)   │     │ (顯示警告)   │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│ COUNT tfm03 │     │ 查詢更早訂單 │
│ TOP 20 記錄 │     │ 剩餘數量 > 0 │
└─────────────┘     └─────────────┘
```

### FIFO 檢查邏輯

1. 取得當前訂單日期（從 `tfm01.fa03`）
2. 查詢同客戶 + 同產品，日期更早的訂單
3. 計算這些訂單的剩餘數量（`fc05 - fc06`）
4. 若有剩餘數量 > 0，則報告違規

## 安全設計

- **唯讀模式**：連線字串使用 `ApplicationIntent=ReadOnly`
- **SQL 白名單**：只允許預定義的 SELECT 查詢
- **安全驗證**：阻擋 INSERT、UPDATE、DELETE、DROP 等危險操作
- **多重語句阻擋**：禁止使用分號串接多個 SQL 語句

## 效能設計

### 查詢效能

FIFO 檢查使用 JOIN 查詢，利用 SQL Server 的查詢優化器自動選擇最佳執行計劃：

```sql
SELECT ... FROM tfm01 t1
INNER JOIN tfm03 t3 ON t3.fc01 = t1.fa01
WHERE t1.fa04 = @customer
  AND t3.fc04 = @product
  AND t1.fa03 < @date
```

**現有索引**：
- `tfm01.I_tfm01_kfa4`: (fa04, fa03, fa01) — 客戶+日期查詢
- `tfm03.I_tfm03_kfc2`: (fc04) — 產品過濾

**目前效能**（23K 筆資料）：約 5ms/次

### 效能預估

| 資料量 | 預估查詢時間 | 狀態 |
|--------|--------------|------|
| 2 萬筆 | ~5ms | ✅ 正常 |
| 10 萬筆 | ~25ms | ✅ 可接受 |
| 50 萬筆 | ~125ms | ⚠️ 考慮優化 |
| 100 萬筆 | ~250ms | ⚠️ 需要優化 |

### 未來優化（如有需要）

如果資料量增長導致查詢變慢，可在 tfm03 建立複合索引：

```sql
CREATE NONCLUSTERED INDEX IX_tfm03_fifo_v1
ON tfm03 (fc04, fc01)
INCLUDE (fc05, fc06, fc10);
```

索引腳本位置：`sql/create_fifo_index.sql`

**注意**：需要 DBA 權限在正式資料庫執行。

## 設定

編輯 `config.py` 修改預設值：

```python
@dataclass
class Config:
    db_server: str = "localhost"      # SQL Server 位址
    db_name: str = "DATAWIN"          # 資料庫名稱
    db_driver: str = "ODBC Driver 17 for SQL Server"
    poll_interval: int = 3            # 輪詢間隔（秒）

    # 客戶過濾 - 只監控這些客戶的訂單
    customer_filter: List[str] = ["496", "497"]  # 空列表 = 監控全部
```

### 客戶過濾說明

由於 ERP 是多人共用的系統，預設會看到所有人的操作。透過 `customer_filter` 設定，可以只監控特定客戶的訂單：

```python
# 只監控客戶 496 和 497
customer_filter: List[str] = ["496", "497"]

# 監控所有客戶（不過濾）
customer_filter: List[str] = []
```

啟動時會顯示過濾狀態：
```
[Monitor] 只監控客戶: 496, 497
[Monitor] 初始化完成，目前有 7854 筆記錄
```

## 單元測試

```bash
# 執行所有測試
pytest tests/test_config.py tests/test_security.py tests/test_queries.py \
       tests/test_utils.py tests/test_checker.py tests/test_safe_executor.py \
       tests/test_monitor.py -v

# 測試結果：23 passed
```

## 警告視窗截圖

視窗會顯示：
- 當前處理的訂單資訊（PI、日期、產品）
- 應優先處理的訂單清單（PI、日期、剩餘數量、已過時間）
- 「我知道了」和「複製清單」按鈕

## 授權

內部使用
