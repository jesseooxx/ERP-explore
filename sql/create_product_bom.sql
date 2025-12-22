-- ============================================
-- 建立產品標準 BOM 結構
-- 模擬 ERP 產品主檔的組合關係功能
-- ============================================

USE DATAWIN;
GO

-- ============================================
-- 步驟 1: 建立產品 BOM 主表
-- ============================================

IF OBJECT_ID('ProductBOM_Master', 'U') IS NOT NULL
    DROP TABLE ProductBOM_Master;
GO

CREATE TABLE ProductBOM_Master (
    ProductCode VARCHAR(20) NOT NULL,      -- 主產品編號
    ComponentCode VARCHAR(20) NOT NULL,    -- 組件編號
    ComponentName VARCHAR(60),             -- 組件名稱
    ComponentDesc VARCHAR(100),            -- 組件說明
    Ratio_Num FLOAT DEFAULT 1.0,          -- 比例分子
    Ratio_Den FLOAT DEFAULT 1.0,          -- 比例分母 (Num/Den)
    IsMain CHAR(1) DEFAULT 'N',           -- Y=主要零件, N=次要
    SupplierCode VARCHAR(10),             -- 供應商代碼
    SupplierName VARCHAR(60),             -- 供應商名稱
    UnitCost FLOAT DEFAULT 0,             -- 單位成本
    Currency VARCHAR(5) DEFAULT 'NT$',    -- 幣別
    LossRate FLOAT DEFAULT 0,             -- 損耗率 (%)
    SeqNo INT,                            -- 序號
    Remark VARCHAR(255),                  -- 備註
    CreateDate DATETIME DEFAULT GETDATE(), -- 建立日期
    UpdateDate DATETIME DEFAULT GETDATE(), -- 更新日期
    PRIMARY KEY (ProductCode, ComponentCode)
);
GO

PRINT '✅ ProductBOM_Master 表已建立';
GO

-- ============================================
-- 步驟 2: 插入 074027 標準 BOM
-- ============================================

PRINT '';
PRINT '插入 074027 標準 BOM...';

INSERT INTO ProductBOM_Master (
    ProductCode, ComponentCode, ComponentName, ComponentDesc,
    Ratio_Num, Ratio_Den, IsMain, SupplierCode, SupplierName,
    UnitCost, Currency, LossRate, SeqNo
) VALUES
-- MAIN 組件 (主要零件)
('074027', '074027-MAIN', '740 SW 60', 'FINISHED SOCKET',
 1.0, 1.0, 'Y', '0735', '萬典實業',
 260.44, 'NT$', 0, 3),

-- LABEL 組件 (次要零件)
('074027', '074027-LABEL', '740 SW 60 產品', 'POLYBAG 使用之貼標',
 1.0, 1.0, 'N', '02291', '台寶數位',
 0.7, 'NT$', 0, 1);

PRINT '✅ 074027 BOM 已插入';
GO

-- ============================================
-- 步驟 3: 驗證結果
-- ============================================

PRINT '';
PRINT '========================================';
PRINT '  074027 標準 BOM 明細';
PRINT '========================================';

SELECT
    SeqNo AS [序號],
    CASE IsMain WHEN 'Y' THEN '主要' ELSE '次要' END AS [類型],
    ComponentCode AS [組件編號],
    ComponentName AS [組件名稱],
    CAST(Ratio_Num AS VARCHAR) + ' / ' + CAST(Ratio_Den AS VARCHAR) AS [比例],
    UnitCost AS [成本],
    Currency AS [幣別],
    SupplierCode AS [供應商代碼],
    SupplierName AS [供應商名稱]
FROM ProductBOM_Master
WHERE ProductCode = '074027'
ORDER BY SeqNo;

GO

-- ============================================
-- 步驟 4: 建立計算函數
-- ============================================

IF OBJECT_ID('dbo.fn_CalcProductBOM') IS NOT NULL
    DROP FUNCTION dbo.fn_CalcProductBOM;
GO

CREATE FUNCTION dbo.fn_CalcProductBOM
(
    @ProductCode VARCHAR(20),
    @OrderQty FLOAT
)
RETURNS TABLE
AS
RETURN
(
    SELECT
        SeqNo AS ComponentSeq,
        ComponentCode,
        ComponentName,
        IsMain,
        Ratio_Num,
        Ratio_Den,
        CAST((@OrderQty * Ratio_Num / Ratio_Den) AS DECIMAL(10,2)) AS RequiredQty,
        UnitCost,
        Currency,
        CAST((@OrderQty * Ratio_Num / Ratio_Den * UnitCost) AS DECIMAL(10,2)) AS TotalCost,
        SupplierCode,
        SupplierName,
        LossRate
    FROM ProductBOM_Master
    WHERE ProductCode = @ProductCode
);
GO

PRINT '✅ BOM 計算函數已建立: fn_CalcProductBOM';
GO

-- ============================================
-- 步驟 5: 測試計算 - 訂購 32 PC
-- ============================================

PRINT '';
PRINT '========================================';
PRINT '  訂購 32 PC 074027 的組件需求';
PRINT '========================================';

SELECT
    ComponentSeq AS [序號],
    ComponentCode AS [組件編號],
    ComponentName AS [組件名稱],
    RequiredQty AS [需求數量],
    UnitCost AS [單價],
    TotalCost AS [小計],
    Currency AS [幣別],
    SupplierName AS [供應商]
FROM dbo.fn_CalcProductBOM('074027', 32)
ORDER BY ComponentSeq;

-- 總成本
SELECT
    SUM(TotalCost) AS [總成本],
    Currency AS [幣別]
FROM dbo.fn_CalcProductBOM('074027', 32)
GROUP BY Currency;

GO

PRINT '';
PRINT '========================================';
PRINT '  使用說明';
PRINT '========================================';
PRINT '';
PRINT '查詢產品標準 BOM:';
PRINT '  SELECT * FROM ProductBOM_Master WHERE ProductCode = ''074027'';';
PRINT '';
PRINT '計算訂單需求:';
PRINT '  SELECT * FROM dbo.fn_CalcProductBOM(''074027'', 32);';
PRINT '';
PRINT '✅ 完成!';
