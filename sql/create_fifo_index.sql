-- ============================================================
-- FIFO 監控系統 - 效能優化索引
-- ============================================================
--
-- 目的：加速 FIFO 違規檢查查詢
--
-- 查詢模式：
--   SELECT ... FROM tfm01 t1
--   INNER JOIN tfm03 t3 ON t3.fc01 = t1.fa01
--   WHERE t1.fa04 = @customer      -- 客戶過濾
--     AND t3.fc04 = @product       -- 產品過濾
--     AND t1.fa03 < @date          -- 日期過濾
--   GROUP BY t1.fa01, t1.fa03
--   HAVING SUM(t3.fc05 - ISNULL(t3.fc06, 0)) > 0
--
-- 預期效果：
--   - 當前 (23K 筆): 5ms → < 1ms
--   - 未來 (100K 筆): 預估 25ms → < 2ms
--   - 未來 (1M 筆): 預估 250ms → < 5ms
--
-- ============================================================

-- 1. 檢查現有索引（執行前先確認）
SELECT
    i.name as index_name,
    i.type_desc,
    c.name as column_name
FROM sys.indexes i
INNER JOIN sys.index_columns ic
    ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c
    ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE i.object_id = OBJECT_ID('tfm03')
ORDER BY i.name, ic.key_ordinal;
GO

-- ============================================================
-- 2. 建立新索引
-- ============================================================

-- 方案 A：最小索引（推薦先試這個）
-- 用於加速 JOIN 和產品過濾
CREATE NONCLUSTERED INDEX IX_tfm03_fifo_v1
ON tfm03 (fc04, fc01)
INCLUDE (fc05, fc06, fc10);
GO

-- 方案 B：完整索引（如果方案 A 不夠快）
-- 包含客戶過濾，適用於客戶過濾的查詢
-- CREATE NONCLUSTERED INDEX IX_tfm03_fifo_v2
-- ON tfm03 (fc10, fc04, fc01)
-- INCLUDE (fc05, fc06);
-- GO

-- ============================================================
-- 3. 驗證索引建立成功
-- ============================================================
SELECT
    i.name as index_name,
    i.type_desc
FROM sys.indexes i
WHERE i.object_id = OBJECT_ID('tfm03')
  AND i.name LIKE 'IX_tfm03_fifo%';
GO

-- ============================================================
-- 4. 測試查詢效能（開啟執行計劃查看）
-- ============================================================
SET STATISTICS TIME ON;
SET STATISTICS IO ON;

-- 測試查詢
SELECT
    t1.fa01 as pi_no,
    t1.fa03 as order_date,
    SUM(t3.fc05 - ISNULL(t3.fc06, 0)) as remaining
FROM tfm01 t1
INNER JOIN tfm03 t3 ON t3.fc01 = t1.fa01
WHERE t1.fa04 = '497'
  AND t3.fc04 = '05671280001'
  AND t1.fa03 < '20250101'
GROUP BY t1.fa01, t1.fa03
HAVING SUM(t3.fc05 - ISNULL(t3.fc06, 0)) > 0
ORDER BY t1.fa03 ASC;

SET STATISTICS TIME OFF;
SET STATISTICS IO OFF;
GO

-- ============================================================
-- 5. 如果需要刪除索引
-- ============================================================
-- DROP INDEX IX_tfm03_fifo_v1 ON tfm03;
-- DROP INDEX IX_tfm03_fifo_v2 ON tfm03;
