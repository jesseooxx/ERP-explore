"""安全模組 - 確保只能執行唯讀查詢"""
import re
from typing import Optional


class SecurityError(Exception):
    """安全違規例外"""
    pass


FORBIDDEN_KEYWORDS = [
    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER',
    'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE', 'MERGE'
]


def validate_query(query: str) -> None:
    """
    驗證 SQL 查詢是否安全。

    Args:
        query: SQL 查詢字串

    Raises:
        SecurityError: 如果查詢不安全
    """
    normalized = query.strip().upper()

    # 檢查 1：必須以 SELECT 開頭
    if not normalized.startswith('SELECT'):
        raise SecurityError("禁止執行非 SELECT 語句")

    # 檢查 2：不能有多重語句（先檢查分號）
    if ';' in query:
        raise SecurityError("禁止多重語句")

    # 檢查 3：不能包含危險關鍵字
    for keyword in FORBIDDEN_KEYWORDS:
        pattern = r'\b' + keyword + r'\b'
        if re.search(pattern, normalized):
            raise SecurityError(f"禁止使用 {keyword}")
