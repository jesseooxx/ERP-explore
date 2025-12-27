"""測試安全查詢執行器"""
import pytest
from unittest.mock import Mock, MagicMock
from fifo_monitor.security import SafeQueryExecutor, SecurityError


def test_executor_allows_select():
    """執行器應允許 SELECT 查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    executor.execute("SELECT * FROM tfm01")
    mock_conn.cursor().execute.assert_called()


def test_executor_blocks_delete():
    """執行器應阻擋 DELETE 查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    with pytest.raises(SecurityError):
        executor.execute("DELETE FROM tfm01")


def test_executor_with_params():
    """執行器應支援參數化查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    executor.execute("SELECT * FROM tfm01 WHERE fa01 = ?", ("PI001",))
    mock_conn.cursor().execute.assert_called_with(
        "SELECT * FROM tfm01 WHERE fa01 = ?", ("PI001",)
    )
