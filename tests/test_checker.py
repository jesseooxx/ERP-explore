"""測試 FIFO 檢查器"""
import pytest
from unittest.mock import Mock, MagicMock
from fifo_monitor.checker import FIFOChecker, FIFOViolation


def test_no_violation_when_no_earlier_orders():
    """沒有更早的訂單時不應報告違規"""
    mock_executor = Mock()
    mock_executor.execute.return_value = Mock(fetchone=Mock(return_value=('20241227',)))
    mock_executor.execute.return_value.fetchall = Mock(return_value=[])

    checker = FIFOChecker(mock_executor)
    result = checker.check('PI001', 'PROD001', 'CUST001')

    assert result is None


def test_violation_when_earlier_order_has_remaining():
    """有更早的訂單有剩餘時應報告違規"""
    mock_executor = Mock()

    # 模擬 GET_ORDER_DATE 返回
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [
        ('20241227',),  # 當前訂單日期
    ]
    mock_cursor.fetchall.return_value = [
        ('PI000', '20240101', 100, 50, 50),  # 更早的訂單有剩餘
    ]
    mock_executor.execute.return_value = mock_cursor

    checker = FIFOChecker(mock_executor)
    result = checker.check('PI001', 'PROD001', 'CUST001')

    assert result is not None
    assert isinstance(result, FIFOViolation)
    assert len(result.earlier_orders) == 1
    assert result.earlier_orders[0]['pi_no'] == 'PI000'
    assert result.earlier_orders[0]['remaining'] == 50
