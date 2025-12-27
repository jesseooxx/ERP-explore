# 成本風險檢查工具

檢查供應商報價是否過時，幫助在回簽客戶訂單前識別價格風險。

## 安裝

確保已安裝相依套件：

```bash
pip install pyodbc
```

## 使用方式

### 基本使用

```bash
# 檢查單一產品
python -m cost_risk_checker.main 284102

# 檢查多個產品
python -m cost_risk_checker.main 284102 284006 310052

# 從檔案讀取
python -m cost_risk_checker.main --file products.txt
```

### 輸出 CSV

```bash
python -m cost_risk_checker.main 284102 284006 --csv output.csv
```

### 調整門檻

```bash
# 成本超過 3 年才視為過時（預設 2 年）
python -m cost_risk_checker.main 284102 --threshold-years 3
```

### 加上標題

```bash
python -m cost_risk_checker.main 284102 --title "PO-2024-12345"
```

## 風險等級說明

| 等級 | 條件 | 建議 |
|------|------|------|
| 🔴 高風險 | 成本 > 2年 且 採購 > 1年 | 回簽前先問工廠 |
| 🟡 中風險 | 成本 > 2年 但 採購 ≤ 1年 | 留意，但工廠較難漲價 |
| 🟢 低風險 | 成本 ≤ 2年 | 正常 |

## 與 Claude Code 整合

1. 將客戶 PDF 訂單丟給 Claude
2. Claude 抽取產品編號
3. Claude 呼叫此工具檢查
4. 回傳風險報告
