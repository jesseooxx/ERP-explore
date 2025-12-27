"""測試工具模組"""
import pytest
from datetime import date
from fifo_monitor.utils import format_elapsed_time


def test_format_years_and_months():
    """超過一年應顯示年和月"""
    # 假設今天是 2025-12-27，訂單日期是 2020-06-15
    order_date = "20200615"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "5年" in result
    assert "6個月" in result


def test_format_months_only():
    """不到一年應只顯示月"""
    order_date = "20250615"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "年" not in result
    assert "6個月" in result


def test_format_days_only():
    """不到一個月應只顯示天"""
    order_date = "20251215"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "年" not in result
    assert "月" not in result
    assert "12天" in result


def test_format_zero_days():
    """同一天應顯示 0 天"""
    order_date = "20251227"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "0天" in result
