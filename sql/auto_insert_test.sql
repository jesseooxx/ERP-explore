-- ============================================
-- 自動插入銷售訂單測試腳本
-- 適用於本地 DATAWIN 資料庫
-- ============================================

USE DATAWIN;
GO

-- ============================================
-- 步驟 1: 查詢目前最大的 S/C 編號
-- ============================================
DECLARE @MaxSC VARCHAR(10);
DECLARE @NewSC VARCHAR(10);
DECLARE @Today VARCHAR(8);

SELECT @MaxSC = MAX(fa01) FROM tfm01;
PRINT '目前最大 S/C 編號: ' + ISNULL(@MaxSC, '(無)');

-- 產生新編號 (最大值 + 1，補零到5位)
SET @NewSC = RIGHT('00000' + CAST(CAST(@MaxSC AS INT) + 1 AS VARCHAR), 5);
SET @Today = CONVERT(VARCHAR(8), GETDATE(), 112);

PRINT '新 S/C 編號: ' + @NewSC;
PRINT '今日日期: ' + @Today;

-- ============================================
-- 步驟 2: 插入主檔 (tfm01)
-- ============================================
PRINT '';
PRINT '=== 插入 tfm01 主檔 ===';

INSERT INTO tfm01 (
    fa01,       -- S/C 編號
    fa02,       -- 類型
    fa03,       -- 建立日期
    fa04,       -- 客戶編號
    fa05,       -- 業務代號
    fa07,       -- 聯絡人
    fa08,       -- 客戶訂單號
    fa09,       -- 狀態
    fa11,       -- 起運港
    fa14,       -- 目的港
    fa17,       -- 貿易條件
    fa18,       -- 貿易條件說明
    fa19,       -- 幣別
    fa20,       -- 匯率
    fa21,       -- 匯率2
    fa32,       -- 預計出貨日
    fa33,       -- 備註
    fa34,       -- 付款條件
    fa37,       -- 總金額 (稍後更新)
    fa63,       -- 完成標記
    fa64        -- 取消標記
) VALUES (
    @NewSC,
    'I',
    @Today,
    '498',                              -- 使用現有客戶
    'I04',                              -- 使用現有業務
    'AUTO TEST CONTACT',
    'AUTO-TEST-' + @Today,
    '1',
    'SHANGHAI',
    'ROTTERDAM',
    'FOB',
    'FOB SHANGHAI',
    'US$',
    30.0,
    1,
    @Today,                             -- 預計出貨日=今天
    'AUTO GENERATED TEST ORDER',
    'BY T/T WITHIN 30 DAYS',
    0,
    'N',
    'N'
);

PRINT 'tfm01 插入完成!';

-- ============================================
-- 步驟 3: 插入明細 (tfm02) - 3 個品項
-- ============================================
PRINT '';
PRINT '=== 插入 tfm02 明細 ===';

-- 品項 1
INSERT INTO tfm02 (
    fb01, fb02, fb03, fb06, fb07, fb09, fb10, fb11, fb12, fb23, fb24, fb26, fb53
) VALUES (
    @NewSC, 1, 'TEST-ITEM-001', 'Test Product A', 'Description line 2',
    100, 'PC', 15.00, 1500.00, 1, '箱', 'CU''FT', 'N'
);

-- 品項 2
INSERT INTO tfm02 (
    fb01, fb02, fb03, fb06, fb07, fb09, fb10, fb11, fb12, fb23, fb24, fb26, fb53
) VALUES (
    @NewSC, 2, 'TEST-ITEM-002', 'Test Product B', 'Another description',
    200, 'PC', 8.50, 1700.00, 1, '箱', 'CU''FT', 'N'
);

-- 品項 3
INSERT INTO tfm02 (
    fb01, fb02, fb03, fb06, fb07, fb09, fb10, fb11, fb12, fb23, fb24, fb26, fb53
) VALUES (
    @NewSC, 3, 'TEST-ITEM-003', 'Test Product C', 'Third item',
    50, 'UNIT', 25.00, 1250.00, 1, '箱', 'CU''FT', 'N'
);

PRINT 'tfm02 插入完成! (3 筆明細)';

-- ============================================
-- 步驟 4: 更新主檔總金額
-- ============================================
PRINT '';
PRINT '=== 更新主檔總金額 ===';

UPDATE tfm01
SET fa37 = (SELECT SUM(fb12) FROM tfm02 WHERE fb01 = @NewSC)
WHERE fa01 = @NewSC;

PRINT '總金額已更新!';

-- ============================================
-- 步驟 5: 驗證結果
-- ============================================
PRINT '';
PRINT '========== 驗證結果 ==========';
PRINT '';

-- 驗證主檔
PRINT '--- tfm01 主檔 ---';
SELECT
    fa01 AS [S/C編號],
    fa03 AS [日期],
    fa04 AS [客戶],
    fa07 AS [聯絡人],
    fa08 AS [客戶訂單號],
    fa11 AS [起運港],
    fa14 AS [目的港],
    fa19 AS [幣別],
    fa37 AS [總金額]
FROM tfm01
WHERE fa01 = @NewSC;

-- 驗證明細
PRINT '';
PRINT '--- tfm02 明細 ---';
SELECT
    fb01 AS [S/C編號],
    fb02 AS [項次],
    fb03 AS [產品編號],
    fb06 AS [品名],
    fb09 AS [數量],
    fb10 AS [單位],
    fb11 AS [單價],
    fb12 AS [金額]
FROM tfm02
WHERE fb01 = @NewSC
ORDER BY fb02;

-- 統計
PRINT '';
PRINT '--- 統計 ---';
SELECT
    COUNT(*) AS [明細筆數],
    SUM(fb09) AS [總數量],
    SUM(fb12) AS [總金額]
FROM tfm02
WHERE fb01 = @NewSC;

PRINT '';
PRINT '========== 測試完成! ==========';
GO
