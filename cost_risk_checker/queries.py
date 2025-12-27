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

    # 取得供應商簡稱（ca03），找不到則用全稱（ca02）
    GET_SUPPLIER_NAME = """
        SELECT COALESCE(NULLIF(ca03, ''), ca02) as supplier_name
        FROM tcm01
        WHERE ca01 = ?
    """

    # 組合關係的虛擬供應商代碼（需要查 BOM 找主件）
    ASSEMBLY_SUPPLIER_CODES = ('B02', 'TEST')

    # 取得 BOM 主件的供應商（de09='Y' 表示主件）
    GET_MAIN_COMPONENT_SUPPLIER = """
        SELECT TOP 1
            de05 as supplier_code
        FROM tdm05
        WHERE de01 = ? AND de09 = 'Y'
    """
