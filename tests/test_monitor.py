"""測試監控器"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from fifo_monitor.monitor import TFM03Monitor


def test_monitor_detects_new_records():
    """監控器應能偵測新記錄"""
    mock_executor = Mock()

    # 模擬：初始化時沒有記錄，之後新增 2 筆
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [
        (100,),  # 初始計數
        (102,),  # 第二次計數（增加了）
    ]
    # 初始化時返回空列表，check 時返回 2 筆新記錄
    mock_cursor.fetchall.side_effect = [
        [],  # initialize 時沒有記錄
        [    # check_for_new_records 時有 2 筆新記錄
            ('PI001', 'PROD001', 'CUST001', '20241227', 100),
            ('PI002', 'PROD002', 'CUST002', '20241227', 200),
        ],
    ]
    mock_executor.execute.return_value = mock_cursor

    monitor = TFM03Monitor(mock_executor)
    monitor.initialize()

    # 模擬偵測到新記錄
    new_records = monitor.check_for_new_records()

    assert len(new_records) == 2


def test_monitor_no_new_records():
    """沒有新記錄時應返回空列表"""
    mock_executor = Mock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [
        (100,),  # 初始
        (100,),  # 沒變
    ]
    mock_executor.execute.return_value = mock_cursor

    monitor = TFM03Monitor(mock_executor)
    monitor.initialize()

    new_records = monitor.check_for_new_records()

    assert new_records == []
