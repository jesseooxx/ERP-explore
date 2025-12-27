"""測試設定模組"""
import pytest
from fifo_monitor.config import Config


def test_config_has_database_settings():
    """設定應包含資料庫連線資訊"""
    config = Config()
    assert hasattr(config, 'db_server')
    assert hasattr(config, 'db_name')
    assert hasattr(config, 'poll_interval')


def test_config_poll_interval_default():
    """預設輪詢間隔應為 3 秒"""
    config = Config()
    assert config.poll_interval == 3
