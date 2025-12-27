"""設定模組"""
from dataclasses import dataclass


@dataclass
class Config:
    """FIFO 監控系統設定"""

    # 資料庫設定
    db_server: str = "localhost"
    db_name: str = "DATAWIN"
    db_driver: str = "ODBC Driver 17 for SQL Server"

    # 監控設定
    poll_interval: int = 3  # 秒

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
