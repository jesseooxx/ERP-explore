"""
生產環境設定模組

使用方式：
1. 複製 .env.example 為 .env
2. 填入公司 SQL Server 連線資訊
3. 執行 python -m fifo_monitor.main_production
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ProductionConfig:
    """FIFO 監控系統 - 生產環境設定"""

    # ========== 資料庫設定 ==========
    # 公司 SQL Server 位址（從環境變數讀取，或使用預設值）
    db_server: str = field(
        default_factory=lambda: os.getenv("FIFO_DB_SERVER", "YOUR_SERVER_NAME")
    )
    db_name: str = field(
        default_factory=lambda: os.getenv("FIFO_DB_NAME", "DATAWIN")
    )
    db_driver: str = "ODBC Driver 17 for SQL Server"

    # ========== 驗證設定 ==========
    # 驗證模式: "windows" 或 "sql"
    auth_mode: str = field(
        default_factory=lambda: os.getenv("FIFO_AUTH_MODE", "windows")
    )
    # SQL 驗證用的帳號密碼（僅 auth_mode="sql" 時需要）
    db_user: Optional[str] = field(
        default_factory=lambda: os.getenv("FIFO_DB_USER")
    )
    db_password: Optional[str] = field(
        default_factory=lambda: os.getenv("FIFO_DB_PASSWORD")
    )

    # ========== 監控設定 ==========
    poll_interval: int = 3  # 秒

    # 客戶過濾 - 空列表 = 監控全部客戶
    # 在公司環境可能需要調整
    customer_filter: List[str] = field(default_factory=list)

    # ========== 連線字串 ==========
    @property
    def connection_string(self) -> str:
        """根據驗證模式產生連線字串"""
        base = (
            f"DRIVER={{{self.db_driver}}};"
            f"SERVER={self.db_server};"
            f"DATABASE={self.db_name};"
        )

        if self.auth_mode.lower() == "windows":
            # Windows 驗證（用網域帳號）
            return base + "Trusted_Connection=yes;ApplicationIntent=ReadOnly;"
        else:
            # SQL Server 驗證（用帳號密碼）
            if not self.db_user or not self.db_password:
                raise ValueError(
                    "SQL 驗證模式需要設定 FIFO_DB_USER 和 FIFO_DB_PASSWORD 環境變數"
                )
            return (
                base +
                f"UID={self.db_user};"
                f"PWD={self.db_password};"
                "ApplicationIntent=ReadOnly;"
            )

    def validate(self) -> None:
        """驗證設定是否完整"""
        if self.db_server == "YOUR_SERVER_NAME":
            raise ValueError(
                "請設定 FIFO_DB_SERVER 環境變數為公司 SQL Server 位址\n"
                "例如: set FIFO_DB_SERVER=192.168.1.100"
            )

        if self.auth_mode.lower() == "sql":
            if not self.db_user:
                raise ValueError("SQL 驗證模式需要 FIFO_DB_USER")
            if not self.db_password:
                raise ValueError("SQL 驗證模式需要 FIFO_DB_PASSWORD")

    def __str__(self) -> str:
        """顯示設定摘要（隱藏密碼）"""
        return (
            f"Server: {self.db_server}\n"
            f"Database: {self.db_name}\n"
            f"Auth: {self.auth_mode}\n"
            f"Poll interval: {self.poll_interval}s\n"
            f"Customer filter: {self.customer_filter or 'ALL'}"
        )
