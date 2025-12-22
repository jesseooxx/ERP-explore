-- DataWin ERP 資料庫還原腳本
-- 適用於 SQL Server 2022

-- 步驟 1: 先查看備份檔內容（確認檔案結構）
RESTORE FILELISTONLY
FROM DISK = N'C:\真桌面\Claude code\ERP explore\BK7.bak';
GO

-- 步驟 2: 還原資料庫到本地
-- 注意：請先執行步驟1，確認 LogicalName 是否正確
-- 如果 LogicalName 不同，請修改下面的 MOVE 參數

RESTORE DATABASE [DATAWIN_LOCAL]
FROM DISK = N'C:\真桌面\Claude code\ERP explore\BK7.bak'
WITH
    MOVE N'DATAWIN' TO N'C:\真桌面\Claude code\ERP explore\DATAWIN_LOCAL.mdf',
    MOVE N'DATAWIN_log' TO N'C:\真桌面\Claude code\ERP explore\DATAWIN_LOCAL_log.ldf',
    REPLACE,
    STATS = 10;
GO

-- 步驟 3: 確認還原成功
SELECT name, state_desc, recovery_model_desc
FROM sys.databases
WHERE name = 'DATAWIN_LOCAL';
GO

-- 步驟 4: 列出所有資料表
USE [DATAWIN_LOCAL];
GO

SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_TYPE
FROM INFORMATION_SCHEMA.TABLES
ORDER BY TABLE_NAME;
GO
