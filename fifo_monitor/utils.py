"""工具函數"""
from datetime import date, datetime
from typing import Optional


def format_elapsed_time(order_date_str: str, today: Optional[date] = None) -> str:
    """
    將訂單日期格式化為已過時間。

    Args:
        order_date_str: 訂單日期字串 (YYYYMMDD 格式)
        today: 今天日期（用於測試），預設為 None 使用實際日期

    Returns:
        格式化的時間字串，如 "5年6個月" 或 "3個月" 或 "12天"
    """
    if today is None:
        today = date.today()

    order_date = datetime.strptime(order_date_str, "%Y%m%d").date()
    delta = today - order_date
    total_days = delta.days

    if total_days < 0:
        return "未來日期"

    # 計算年月
    years = total_days // 365
    remaining_days = total_days % 365
    months = remaining_days // 30
    days = remaining_days % 30

    if years > 0:
        return f"{years}年{months}個月"
    elif months > 0:
        return f"{months}個月"
    else:
        return f"{total_days}天"
