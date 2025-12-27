"""SQL 查詢 - 成本風險檢查使用的查詢"""


class CostRiskQueries:
    """成本風險檢查 SQL 查詢"""

    # 取得產品的最新供應商成本（按報價日期 ce07 最大）
    GET_LATEST_SUPPLIER_COST = """
        SELECT TOP 1
            ce011 as supplier_code,
            ce02 as product_code,
            ce06 as unit_cost,
            ce05 as currency,
            ce07 as quote_date
        FROM tcm05
        WHERE ce02 = ?
        ORDER BY ce07 DESC
    """

    # 取得產品的最後採購日期
    GET_LAST_PURCHASE_DATE = """
        SELECT TOP 1
            t1.ga03 as po_date,
            t1.ga01 as po_no
        FROM tgm01 t1
        INNER JOIN tgm02 t2 ON t2.gb01 = t1.ga01
        WHERE t2.gb03 = ?
        ORDER BY t1.ga03 DESC
    """

    # 取得供應商名稱
    GET_SUPPLIER_NAME = """
        SELECT ca02 as supplier_name
        FROM tcm01
        WHERE ca01 = ?
    """
