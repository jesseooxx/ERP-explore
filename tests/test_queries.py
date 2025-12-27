"""測試查詢模組"""
import pytest
from fifo_monitor.queries import FIFOQueries
from fifo_monitor.security import validate_query, SecurityError


def test_all_queries_are_safe():
    """所有預定義的查詢都應該通過安全檢查"""
    queries = [
        FIFOQueries.COUNT_TFM03,
        FIFOQueries.GET_NEW_SCHEDULES,
        FIFOQueries.GET_ORDER_DATE,
        FIFOQueries.GET_EARLIER_ORDERS_WITH_REMAINING,
    ]
    for query in queries:
        validate_query(query)  # 不應拋出例外


def test_queries_are_select_only():
    """所有查詢都應該是 SELECT"""
    queries = [
        FIFOQueries.COUNT_TFM03,
        FIFOQueries.GET_NEW_SCHEDULES,
        FIFOQueries.GET_ORDER_DATE,
        FIFOQueries.GET_EARLIER_ORDERS_WITH_REMAINING,
    ]
    for query in queries:
        assert query.strip().upper().startswith('SELECT')
