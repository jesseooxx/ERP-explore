"""測試安全模組"""
import pytest
from fifo_monitor.security import SecurityError, validate_query


def test_select_query_allowed():
    """SELECT 查詢應該被允許"""
    query = "SELECT * FROM tfm01"
    validate_query(query)  # 不應拋出例外


def test_insert_query_blocked():
    """INSERT 查詢應該被阻擋"""
    query = "INSERT INTO tfm01 VALUES (1)"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_update_query_blocked():
    """UPDATE 查詢應該被阻擋"""
    query = "UPDATE tfm01 SET fa01 = 'x'"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_delete_query_blocked():
    """DELETE 查詢應該被阻擋"""
    query = "DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_drop_query_blocked():
    """DROP 查詢應該被阻擋"""
    query = "DROP TABLE tfm01"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_multi_statement_blocked():
    """多語句查詢應該被阻擋"""
    query = "SELECT * FROM tfm01; DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="多重語句"):
        validate_query(query)


def test_case_insensitive_blocking():
    """關鍵字檢查應不分大小寫"""
    query = "select * from tfm01; delete from tfm01"
    with pytest.raises(SecurityError):
        validate_query(query)


def test_non_select_start_blocked():
    """非 SELECT 開頭的查詢應被阻擋"""
    query = "WITH cte AS (SELECT 1) DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="非 SELECT"):
        validate_query(query)
