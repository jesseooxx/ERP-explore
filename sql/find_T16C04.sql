-- 查詢 S/C 編號 T16C04 的訂單內容
USE DATAWIN;
GO

-- 1. 查詢主檔
PRINT '=== tfm01 主檔 ===';
SELECT * FROM tfm01 WHERE fa01 = 'T16C04';

-- 2. 查詢明細
PRINT '';
PRINT '=== tfm02 明細 (品項清單) ===';
SELECT
    fb01 AS [S/C編號],
    fb02 AS [項次],
    fb03 AS [產品編號],
    fb06 AS [品名1],
    fb07 AS [品名2],
    fb09 AS [數量],
    fb10 AS [單位],
    fb11 AS [單價],
    fb12 AS [金額]
FROM tfm02
WHERE fb01 = 'T16C04'
ORDER BY fb02;

-- 3. 如果找不到，試試模糊搜尋
PRINT '';
PRINT '=== 模糊搜尋 (包含 T16C04) ===';
SELECT fa01, fa03, fa04, fa07, fa08
FROM tfm01
WHERE fa01 LIKE '%T16C04%' OR fa08 LIKE '%T16C04%';

-- 4. 也查詢 tqm01/tqm02 (報價單)
PRINT '';
PRINT '=== tqm01 報價主檔 ===';
SELECT * FROM tqm01 WHERE qa01 = 'T16C04';

PRINT '';
PRINT '=== tqm02 報價明細 ===';
SELECT * FROM tqm02 WHERE qb01 = 'T16C04';
