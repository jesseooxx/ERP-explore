# ERP UI「查詢主檔」程式研究報告

**研究日期**: 2025-12-18
**目標**: 找出查詢主檔程式的資料來源和 SQL 表格對照

---

## 從截圖擷取的資訊

### 查詢主檔視窗內容

```
組合:
(PuTai_iqm01) 報價單組合關係檔，查看先前報加加，I804000059A
(pdm08) 組合關係與顯示，支援組合加加，I407000180A
(qem21) 登錄產品組合關係，協議產品，I512000003A
(qdm19) 報稅上繳報稅組合關係，查看加斯達加加，WEB15000...
(tem05) 報價，訂單  產品組合
(tidm05) 產品組合關係檔，查看詢加加I207000046A
(ttem05) 報價，訂單  產品組合
```

---

## 資料來源分析

### 發現的表格

| 表格名稱 | 說明 | 用途 | 狀態 |
|---------|------|------|------|
| **dsinquiry** | 查詢定義主表 | 儲存自訂查詢 | 本地空白 |
| **tdm05** | 產品標準 BOM | 產品組合關係 | ✅ 有資料 |
| **tem05** | 訂單 BOM | 訂單產品組合 | ✅ 有資料 |
| **ttem05** | (推測) 報價 BOM | 報價產品組合 | 未查詢 |
| **tidm05** | (推測) 另一種組合 | 產品組合 | 未查詢 |
| **qem21** | 客戶專屬 BOM | 客戶產品組合 | 本地空白 |
| **qdm19** | (推測) 報稅組合 | 報稅相關 | 未查詢 |
| **pdm08** | (推測) 採購組合 | 採購顯示 | 本地空白 |
| **PuTai_iqm01** | 客戶定制表 | 普泰客戶專用 | 未查詢 |

---

## DLL 中發現的 SQL 查詢

### 從 xtf1i01.dll 和 xtq8i20.dll 解析出的 SQL

#### 查詢 1: 檢查產品是否有標準 BOM
```sql
SELECT de01 FROM tdm05 WHERE de01='%s'
```
**說明**: 檢查產品編號是否存在於標準 BOM 主檔

#### 查詢 2: 檢查客戶專屬 BOM
```sql
SELECT 0 FROM qem21 WHERE qeu00 = '%s' AND qeu01 = '%s'
```
**說明**:
- qeu00 = 客戶編號 (fa04)
- qeu01 = 產品編號 (fb03)

#### 查詢 3: 取得客戶專屬組件
```sql
SELECT ee03 = qeu02 FROM qem21
WHERE qeu00 = '%s' AND qeu01 = '%s' AND ...
```

#### 查詢 4: 檢查是否有組合項目
```sql
select 1 from tdm05 where de01='%s'
```

#### 查詢 5: 排程數量查詢
```sql
SELECT SUM(ISNULL(fc05,0)), SUM(ISNULL(fc06,0)), SUM(ISNULL(fc07,0))
FROM tfm03
WHERE fc01='%s' AND fc04='%s'
```

---

## 查詢優先順序邏輯

根據 DLL 中的 SQL 順序推測：

```
1. 先查 qem21 (客戶專屬 BOM)
   ↓
   如果找到 → 使用客戶專屬設定
   ↓
   如果沒找到 ↓

2. 再查 tdm05 (產品標準 BOM)
   ↓
   如果找到 → 使用標準設定
   ↓
   如果沒找到 ↓

3. 顯示錯誤: "該產品沒有組合項目!"
   (The Item Has No Assamble Items!)
```

---

## 「查詢主檔」視窗的資料結構

### dsinquiry 表結構

| 欄位 | 型態 | 說明 |
|------|------|------|
| **tabname** | varchar(40) | 資料表名稱 |
| **qryno** | varchar(40) | 查詢編號 |
| **qrydesc** | varchar(80) | 查詢說明 |
| **qrydata** | image | 查詢資料 (binary) |
| **qryfield** | image | 查詢欄位 (binary) |

### 截圖內容解析

查詢主檔視窗顯示的格式：
```
(表格名稱) 查詢說明，額外資訊，程式編號
```

範例：
```
(PuTai_iqm01) 報價單組合關係檔，查看先前報加加，I804000059A
         ↑              ↑                    ↑            ↑
    表格名稱        功能說明              額外說明      程式編號
```

---

## 所有 *m05 表格對照

### 從截圖和資料庫推測

| 表格 | 全名推測 | 用途 | 本地狀態 |
|------|---------|------|----------|
| **tdm05** | Transaction Detail m05 | 產品標準 BOM | ✅ 有資料 (284102等) |
| **tem05** | Transaction Event m05 | 訂單專屬 BOM | ✅ 有資料 (T16C04等) |
| **ttem05** | (TT?) em05 | 報價產品組合 | 未查詢 |
| **tidm05** | (TID?) m05 | 產品組合關係檔 | 未查詢 |

---

## 客戶定制表系列

### 從截圖推測的客戶專屬表格

| 表格 | 客戶 | 用途 |
|------|------|------|
| PuTai_iqm01 | 普泰 | 報價單組合關係 |
| (其他客戶可能也有類似表格) | | |

### qem21 - 客戶專屬產品組合

| 欄位 | 推測用途 |
|------|----------|
| qeu00 | 客戶編號 |
| qeu01 | 產品編號 |
| qeu02 | 組件編號 |
| qeu03/qeu04 | 比例 |
| qeu05 | 供應商 |

**特性**:
- 允許為特定客戶設定專屬的產品組合
- 優先於標準 BOM (tdm05)
- 本地備份中無資料（可能是新功能）

---

## UI 查詢流程完整解析

### 當使用者點選「產品組合」時

```
1. UI 觸發事件 (OnClick, OnEnter 等)
   ↓
2. xtf1i01.dll 執行查詢邏輯
   ↓
3. 第一優先: 查詢客戶專屬 BOM
   SQL: SELECT qeu02 FROM qem21
        WHERE qeu00 = '客戶編號' AND qeu01 = '產品編號'
   ↓
   如果找到 → 使用 qem21 資料
   ↓
   如果沒找到 ↓

4. 第二優先: 查詢產品標準 BOM
   SQL: SELECT de01 FROM tdm05 WHERE de01 = '產品編號'
   ↓
   如果找到 → 從 tdm05 讀取組合
   ↓
   如果沒找到 ↓

5. 顯示錯誤訊息
   "該產品沒有組合項目!"

6. 如果找到 BOM → 複製到 tem05 (訂單專屬)
   SQL: INSERT INTO tem05 SELECT ... FROM tdm05

7. 根據訂購數量計算需求
   需求數量 = tfm02.fb09 × (de03/de04)

8. 顯示組合視窗
   列出所有組件及計算結果
```

---

## 查詢主檔的資料儲存

### 方案 A: 資料庫表格 (dsinquiry)

```sql
-- 理論上應該在 dsinquiry 儲存
INSERT INTO dsinquiry (tabname, qryno, qrydesc, qrydata)
VALUES
('tdm05', 'tdm05', '產品組合關係檔', BINARY查詢定義),
('tem05', 'tem05', '報價，訂單  產品組合', BINARY查詢定義);
```

**問題**: 本地備份中 dsinquiry 是空的

### 方案 B: 硬編碼在 DLL

從 `UserQueryDLL.dll` 和 `xtf1i01.dll` 的字串可以看到：
- 查詢邏輯直接寫在 DLL 中
- 表格名稱和說明文字硬編碼
- 不依賴資料庫的查詢定義表

### 方案 C: XML 或設定檔

可能在：
- X:\EXE\*.xml
- 註冊表
- 其他設定檔

---

## 關鍵發現

### 從 DLL 字串解析

**xtf1i01.dll** 包含的關鍵邏輯：

```c
// 偽代碼還原
if (exists("SELECT 1 FROM tdm05 WHERE de01='" + itemNo + "'")) {
    // 有標準 BOM
    showBOMWindow(itemNo);
} else if (exists("SELECT 0 FROM qem21 WHERE qeu00='" + custNo + "' AND qeu01='" + itemNo + "'")) {
    // 有客戶專屬 BOM
    showCustomerBOM(custNo, itemNo);
} else {
    // 沒有 BOM
    MessageBox("該產品沒有組合項目!");
}
```

**錯誤訊息**（多語言）：
- 英文: "The Item Has No Assamble Items!"
- 簡體: "该产品没有组合产品!"
- 繁體: "該產品無組合項目!"

---

## 完整表格關聯總結

### BOM 相關表格層級

```
┌─────────────────────────────────────┐
│  層級 1: 客戶專屬 BOM (最高優先)      │
│  ┌─────────┐                        │
│  │ qem21   │ 客戶+產品 BOM            │
│  └─────────┘                        │
│  qeu00=客戶, qeu01=產品, qeu02=組件  │
└─────────────────────────────────────┘
              ↓ (如果沒有)

┌─────────────────────────────────────┐
│  層級 2: 產品標準 BOM (次優先)        │
│  ┌─────────┐                        │
│  │ tdm05   │ 產品標準 BOM            │
│  └─────────┘                        │
│  de01=產品, de02=組件               │
└─────────────────────────────────────┘
              ↓ (複製到)

┌─────────────────────────────────────┐
│  層級 3: 訂單專屬 BOM (實際使用)      │
│  ┌─────────┐                        │
│  │ tem05   │ 訂單 BOM                │
│  └─────────┘                        │
│  ee011=訂單, ee02=產品, ee03=組件   │
└─────────────────────────────────────┘
```

---

## 查詢主檔視窗資料來源

### 推測的實現方式

#### 方案 A: 硬編碼在 DLL
- **位置**: `X:\EXE\UserQueryDLL.dll`
- **方式**: C/C++ 程式碼中定義查詢清單
- **優點**: 不需資料庫，執行快速
- **缺點**: 修改需要重新編譯 DLL

#### 方案 B: 資料庫表格 (dsinquiry)
- **位置**: `dsinquiry` 表
- **方式**: 從表格讀取查詢定義
- **狀態**: 本地備份為空（正式環境可能有資料）

#### 方案 C: 混合方式
- 常用查詢硬編碼在 DLL
- 自訂查詢儲存在 dsinquiry
- 動態組合顯示清單

---

## 查詢主檔的表格命名規則解析

### 從截圖內容推測

| 顯示文字 | 表格 | 模組前綴 | 說明 |
|---------|------|----------|------|
| PuTai_iqm01 | PuTai_iqm01 | 客戶名_iqm | 客戶定制查詢 |
| pdm08 | pdm08 | pd | 採購相關 |
| qem21 | qem21 | qe | 查詢/報價相關 |
| qdm19 | qdm19 | qd | 查詢明細? |
| tem05 | tem05 | te | 暫存/事件 |
| tidm05 | tidm05 | tid | 交易ID? |
| ttem05 | ttem05 | tte | 暫存交易? |

### 客戶定制表命名

格式: `{客戶名稱}_{模組}{表序號}`

範例：
- `PuTai_iqm01` = 普泰_inquiry/quotation_m01
- `wangpin_kqm02` = 旺品_庫存查詢_m02
- `zhonggui_kqm01` = 中規_庫存查詢_m01

---

## 相關 DLL 檔案

| DLL 檔案 | 大小 | 用途 |
|---------|------|------|
| **UserQueryDLL.dll** | (未確認) | 使用者查詢功能 |
| **xtf1i01.dll** | 5.08 MB | 銷售訂單主程式 |
| **xtq8i20.dll** | (未確認) | 報價單相關 |

### DLL 中的關鍵字串

| 字串 | 說明 |
|------|------|
| `select 1 from tdm05 where de01='%s'` | 檢查標準 BOM |
| `SELECT ee03 = qeu02 FROM qem21 WHERE...` | 查客戶 BOM |
| `The Item Has No Assamble Items!` | 錯誤訊息 |
| `該產品無組合項目!` | 錯誤訊息 (繁體) |

---

## 實際應用：如何找到所有查詢

### 方法 1: 查詢所有 *m05 表格

```sql
-- 列出所有名稱包含 m05 的表格
SELECT TABLE_NAME,
       (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS c WHERE c.TABLE_NAME = t.TABLE_NAME) AS 欄位數
FROM INFORMATION_SCHEMA.TABLES t
WHERE TABLE_NAME LIKE '%m05%'
ORDER BY TABLE_NAME;
```

### 方法 2: 從 DLL 提取表格名稱

```bash
# 從所有 DLL 提取可能的表格名稱
strings /x/EXE/*.dll | grep -E "^[a-z]+m[0-9]{2}$" | sort | uniq
```

### 方法 3: 查詢系統資料表

```sql
-- 列出所有使用者表格
SELECT name FROM sys.tables
WHERE name LIKE '%05%' OR name LIKE '%bom%' OR name LIKE '%asm%'
ORDER BY name;
```

---

## 完整 BOM 表格清單

根據研究結果，ERP 系統中的 BOM 相關表格：

| 層級 | 表格 | 主鍵 | 優先序 | 說明 |
|------|------|------|--------|------|
| 1 | qem21 | (qeu00, qeu01, qeu02) | 最高 | 客戶專屬 BOM |
| 2 | tdm05 | (de01, de02) | 高 | 產品標準 BOM |
| 3 | tem05 | (ee011, ee02, ee03) | 中 | 訂單專屬 BOM |
| - | ttem05 | (推測類似 tem05) | - | 報價 BOM? |
| - | tidm05 | (推測類似 tdm05) | - | 另一種產品 BOM? |

---

## SQL 查詢範本

### 查詢產品的所有可能 BOM 來源

```sql
-- 綜合查詢：檢查產品在所有 BOM 表中的資料
SELECT '客戶專屬BOM (qem21)' AS 來源, qeu00 AS 客戶, qeu01 AS 產品, COUNT(*) AS 組件數
FROM qem21
WHERE qeu01 = '284102'
GROUP BY qeu00, qeu01

UNION ALL

SELECT '產品標準BOM (tdm05)', '', de01, COUNT(*)
FROM tdm05
WHERE de01 = '284102'
GROUP BY de01

UNION ALL

SELECT '訂單BOM (tem05)', ee011, ee02, COUNT(*)
FROM tem05
WHERE ee02 = '284102'
GROUP BY ee011, ee02;
```

### 完整 BOM 查詢 (模擬 ERP 邏輯)

```sql
DECLARE @CustNo VARCHAR(10) = '491';  -- 客戶編號
DECLARE @ItemNo VARCHAR(20) = '284102'; -- 產品編號
DECLARE @SCNo VARCHAR(10) = 'T16C04';   -- 訂單編號

-- Step 1: 先查客戶專屬
IF EXISTS (SELECT 1 FROM qem21 WHERE qeu00 = @CustNo AND qeu01 = @ItemNo)
BEGIN
    PRINT '使用客戶專屬 BOM (qem21)';
    SELECT qeu02 AS 組件, qeu03/qeu04 AS 比例, qeu05 AS 供應商
    FROM qem21
    WHERE qeu00 = @CustNo AND qeu01 = @ItemNo;
END
-- Step 2: 再查產品標準
ELSE IF EXISTS (SELECT 1 FROM tdm05 WHERE de01 = @ItemNo)
BEGIN
    PRINT '使用產品標準 BOM (tdm05)';
    SELECT de02 AS 組件, de03/de04 AS 比例, de05 AS 供應商
    FROM tdm05
    WHERE de01 = @ItemNo;
END
ELSE
BEGIN
    PRINT '該產品沒有組合項目!';
END
```

---

## 結論

1. **查詢主檔視窗** 顯示的資料可能是：
   - 硬編碼在 `UserQueryDLL.dll`
   - 或從 `dsinquiry` 讀取（正式環境有資料）

2. **BOM 查詢優先順序**：
   - qem21 (客戶專屬) > tdm05 (產品標準) > 錯誤訊息

3. **實際使用的 BOM**：
   - 從 qem21 或 tdm05 複製到 tem05
   - tem05 是訂單專屬，可調整

4. **截圖中的表格** 都是組合相關的不同實現：
   - 針對不同客戶 (PuTai_iqm01)
   - 針對不同單據類型 (tem05, ttem05)
   - 針對不同功能 (pdm08, qdm19)

---

## 待確認項目

### 需要連接正式環境才能查詢：

1. dsinquiry 的完整內容
2. qem21 的實際資料
3. ttem05, tidm05 等表格的結構
4. PuTai_iqm01 等客戶定制表

### 或者：

反編譯 `UserQueryDLL.dll` 查看完整邏輯
