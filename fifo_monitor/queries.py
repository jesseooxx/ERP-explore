"""SQL 查詢白名單 - 只有這些查詢可以被執行"""


class FIFOQueries:
    """FIFO 監控系統使用的 SQL 查詢"""

    # 計算 tfm03 記錄數
    COUNT_TFM03 = """
        SELECT COUNT(*) FROM tfm03
    """

    # 取得最新的排程記錄（用於偵測新增）
    GET_NEW_SCHEDULES = """
        SELECT TOP 20
            fc01 as pi_no,
            fc04 as product,
            fc10 as customer,
            fc02 as schedule_date,
            fc05 as scheduled_qty
        FROM tfm03
        ORDER BY fc01 DESC, fc02 DESC
    """

    # 取得訂單日期
    GET_ORDER_DATE = """
        SELECT fa03
        FROM tfm01
        WHERE fa01 = ?
    """

    # 查詢同客戶+同產品，更早的訂單是否有剩餘
    GET_EARLIER_ORDERS_WITH_REMAINING = """
        SELECT
            t1.fa01 as pi_no,
            t1.fa03 as order_date,
            SUM(t3.fc05) as total_scheduled,
            SUM(ISNULL(t3.fc06, 0)) as total_shipped,
            SUM(t3.fc05 - ISNULL(t3.fc06, 0)) as remaining
        FROM tfm01 t1
        INNER JOIN tfm03 t3 ON t3.fc01 = t1.fa01
        WHERE t3.fc10 = ?
          AND t3.fc04 = ?
          AND t1.fa03 < ?
        GROUP BY t1.fa01, t1.fa03
        HAVING SUM(t3.fc05 - ISNULL(t3.fc06, 0)) > 0
        ORDER BY t1.fa03 ASC
    """
