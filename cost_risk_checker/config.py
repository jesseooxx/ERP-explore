"""設定模組"""
from dataclasses import dataclass


@dataclass
class Config:
    """成本風險檢查系統設定"""

    # 資料庫設定
    db_server: str = "localhost"
    db_name: str = "DATAWIN"
    db_driver: str = "ODBC Driver 17 for SQL Server"

    # 風險門檻設定（月份）
    cost_stale_threshold_months: int = 24  # 成本超過 2 年視為過時
    purchase_recent_threshold_months: int = 12  # 1 年內有採購視為近期

    # 連線字串
    @property
    def connection_string(self) -> str:
        return (
            f"DRIVER={{{self.db_driver}}};"
            f"SERVER={self.db_server};"
            f"DATABASE={self.db_name};"
            "Trusted_Connection=yes;"
            "ApplicationIntent=ReadOnly;"
        )
