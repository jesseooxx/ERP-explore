-- ============================================
-- 自動計算 BOM 組合數量腳本
-- 模擬 ERP 「點選數量欄位」的計算邏輯
-- ============================================

USE DATAWIN;
GO

-- 設定要查詢的訂單和產品
DECLARE @SCNo VARCHAR(10) = 'T16C04';
DECLARE @ItemNo VARCHAR(20) = '074027';

PRINT '========================================';
PRINT '  BOM 組合數量計算';
PRINT '========================================';
PRINT '';

-- 查詢主產品數量
DECLARE @MainQty FLOAT;
SELECT @MainQty = fb09
FROM tfm02
WHERE fb01 = @SCNo AND fb03 = @ItemNo;

PRINT 'S/C 編號: ' + @SCNo;
PRINT '產品編號: ' + @ItemNo;
PRINT '訂購數量: ' + CAST(@MainQty AS VARCHAR) + ' PC';
PRINT '';
PRINT '========================================';
PRINT '  組合明細';
PRINT '========================================';

-- 計算並顯示各組件需求數量
SELECT
    ee07 AS [序號],
    ee03 AS [組件編號],
    CASE
        WHEN ee03 LIKE '%LABEL%' THEN '標籤'
        WHEN ee03 LIKE '%MAIN%' THEN '主體'
        WHEN ee03 LIKE '%BAG%' THEN '袋標'
        WHEN ee03 LIKE '%CTN%' THEN '箱標'
        ELSE '其他'
    END AS [類型],
    ee05 AS [比例],
    CAST((@MainQty * ee04 / ee05) AS DECIMAL(10,2)) AS [需求數量],
    'PC' AS [單位],
    ee06 AS [供應商],
    CASE ee10
        WHEN 'Y' THEN '是'
        WHEN 'N' THEN '否'
        ELSE '-'
    END AS [主要零件]
FROM tem05
WHERE ee011 = @SCNo AND ee02 = @ItemNo
ORDER BY ee07;

PRINT '';
PRINT '========================================';
PRINT '  成本計算';
PRINT '========================================';

-- 假設有成本資料，計算總成本
-- (實際系統會呼叫 sp_tfm02_subitemcost)
DECLARE @TotalCost FLOAT = 0;

-- 這裡可以加入實際的成本查詢邏輯
-- 從供應商報價或歷史成本中取得

PRINT '主產品數量: ' + CAST(@MainQty AS VARCHAR);
PRINT '組件種類: ' + CAST((SELECT COUNT(*) FROM tem05 WHERE ee011 = @SCNo AND ee02 = @ItemNo) AS VARCHAR) + ' 項';
PRINT '';
PRINT '✅ 計算完成!';

GO

-- ============================================
-- 通用函數：計算任意產品的 BOM
-- ============================================

IF OBJECT_ID('dbo.fn_CalculateBOM') IS NOT NULL
    DROP FUNCTION dbo.fn_CalculateBOM;
GO

CREATE FUNCTION dbo.fn_CalculateBOM
(
    @SCNo VARCHAR(10),
    @ItemNo VARCHAR(20)
)
RETURNS TABLE
AS
RETURN
(
    SELECT
        t2.ee07 AS ComponentSeq,
        t2.ee03 AS ComponentCode,
        t2.ee05 AS Ratio,
        CAST((t1.fb09 * t2.ee04 / t2.ee05) AS DECIMAL(10,2)) AS RequiredQty,
        t1.fb10 AS Unit,
        t2.ee06 AS Supplier,
        t2.ee10 AS IsPrimary
    FROM tfm02 t1
    INNER JOIN tem05 t2 ON t2.ee011 = t1.fb01 AND t2.ee02 = t1.fb03
    WHERE t1.fb01 = @SCNo AND t1.fb03 = @ItemNo
);
GO

-- 使用範例：
-- SELECT * FROM dbo.fn_CalculateBOM('T16C04', '074027');

PRINT '';
PRINT '✅ BOM 計算函數已建立: fn_CalculateBOM';
PRINT '';
PRINT '使用方式:';
PRINT '  SELECT * FROM dbo.fn_CalculateBOM(''訂單編號'', ''產品編號'');';
PRINT '';
