-- 尋找訂單相關的資料表
USE DATAWIN;
GO

-- 1. 列出所有可能與訂單相關的資料表
SELECT TABLE_NAME,
       (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS c WHERE c.TABLE_NAME = t.TABLE_NAME) AS 欄位數
FROM INFORMATION_SCHEMA.TABLES t
WHERE TABLE_TYPE = 'BASE TABLE'
  AND (TABLE_NAME LIKE '%order%'
       OR TABLE_NAME LIKE '%qo%'      -- 報價訂單 Quote Order
       OR TABLE_NAME LIKE '%tq%'      -- 報價/詢價 Quotation
       OR TABLE_NAME LIKE '%tf%'      -- 運輸/Sales Contract
       OR TABLE_NAME LIKE '%td%'      -- 交易明細 Transaction Detail
       OR TABLE_NAME LIKE '%so%'      -- Sales Order
       OR TABLE_NAME LIKE '%po%'      -- Purchase Order
       OR TABLE_NAME LIKE '%sale%'
       OR TABLE_NAME LIKE '%purchase%')
ORDER BY TABLE_NAME;
GO

-- 2. 查看 tfm01 (S/C 主檔) 結構
SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'tfm01'
ORDER BY ORDINAL_POSITION;
GO

-- 3. 查看 tfm01 範例資料
SELECT TOP 10 * FROM tfm01;
GO

-- 4. 查看 tqm01 (報價主檔) 如果存在
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'tqm01')
BEGIN
    SELECT TOP 10 * FROM tqm01;
END
GO
