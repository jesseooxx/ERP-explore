# 貿易模組文檔索引

這是一個輕量級的文檔索引系統，讓 AI 能快速查找相關章節，避免上下文爆炸。

## 使用方式

### 1. 查詢流程

當你（使用者）問到關於貿易模組的問題時，AI 會：

```
你問：「如何處理應收帳款？」
  ↓
AI 讀取：keywords.json (~825 tokens)
  ↓
定位到：ch23 (應收帳款)
  ↓
只載入：chunks/ch23.md (~1161 tokens)
  ↓
回答你的問題
總消耗：~2000 tokens（而不是 210,000 tokens）
```

### 2. 檔案結構

```
trade-module/
├── keywords.json      # 關鍵字索引 (~825 tokens)
├── toc.json           # 章節目錄 (~899 tokens)
└── chunks/            # 章節內容（39 個文件）
    ├── ch01.md        # 貿易上線
    ├── ch23.md        # 應收帳款
    └── ...
```

### 3. 索引統計

| 項目 | 大小 | Token 估算 |
|------|------|-----------|
| keywords.json | 3,303 bytes | ~825 tokens |
| toc.json | 3,597 bytes | ~899 tokens |
| 平均每章 | 4,647 bytes | ~1,161 tokens |
| **典型查詢** | | **~2,000 tokens** |
| **原始 HTML** | 10 MB | **~210,000 tokens** |
| **節省率** | | **99%** |

## AI 查詢指南

### 查詢步驟

**步驟 1：讀取關鍵字索引**
```python
# 讀取 keywords.json
keywords = json.load("keywords.json")
```

**步驟 2：關鍵字匹配**
```python
# 例如：查詢「應收帳款」
if "應收" in keywords or "帳款" in keywords:
    chapters = keywords["應收"]  # 返回 ["ch23"]
```

**步驟 3：載入相關章節**
```python
# 只讀取需要的章節
content = read("chunks/ch23.md")
```

**步驟 4：回答問題**
- 基於載入的章節內容回答
- 如需要多個章節，可載入多個（但盡量控制在 3-5 個以內）

### 常見關鍵字映射

| 問題類型 | 關鍵字 | 相關章節 |
|---------|--------|---------|
| 應收帳款 | 應收、帳款 | ch23 |
| 應付帳款 | 應付、帳款 | ch24 |
| 訂單管理 | 訂單 | ch12, ch20 |
| 出貨流程 | 出貨 | ch12, ch14, ch18 |
| 採購管理 | 採購 | ch12, ch21 |
| 報價作業 | 報價 | ch11, ch17 |
| 系統設定 | 設定、公司、權限 | ch07 |
| 客戶資料 | 客戶 | ch08 |
| 廠商資料 | 廠商 | ch08 |
| 產品資料 | 產品 | ch08 |

## 重建索引

如果需要重新生成索引：

```bash
cd "C:\真桌面\Claude code\ERP explore"
python build_trade_index.py
```

這個腳本會：
1. 讀取 HTML 文檔
2. 提取 39 個章節
3. 生成 keywords.json 和 toc.json
4. 將每個章節轉換為獨立的 Markdown 文件
