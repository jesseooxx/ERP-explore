# FIFO 訂單監控系統

背景監控程式，當 ERP 系統新增排程時自動檢查 FIFO 違規並彈窗警告。

## 功能

- 每 3 秒輪詢 SQL Server 的 `tfm03` 表格
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

### 正式模式（連接資料庫）

```bash
python -m fifo_monitor.main
```

### Demo 模式（不需資料庫）

```bash
python -m fifo_monitor.demo
```

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
├── __init__.py        # 套件初始化
├── config.py          # 資料庫連線設定
├── security.py        # SQL 安全驗證（只允許 SELECT）
├── queries.py         # SQL 查詢白名單
├── utils.py           # 時間格式化工具
├── checker.py         # FIFO 違規檢查邏輯
├── monitor.py         # tfm03 新增記錄偵測
├── alert.py           # tkinter 警告視窗
├── main.py            # 正式模式入口
├── demo.py            # Demo 模式入口
├── test_insert.py     # 測試：查詢現有資料
└── test_trigger.py    # 測試：插入資料觸發監控
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

## 設定

編輯 `config.py` 修改預設值：

```python
@dataclass
class Config:
    db_server: str = "localhost"      # SQL Server 位址
    db_name: str = "DATAWIN"          # 資料庫名稱
    db_driver: str = "ODBC Driver 17 for SQL Server"
    poll_interval: int = 3            # 輪詢間隔（秒）
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
