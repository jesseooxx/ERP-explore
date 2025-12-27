"""FIFO 檢查器"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from fifo_monitor.queries import FIFOQueries
from fifo_monitor.utils import format_elapsed_time


@dataclass
class FIFOViolation:
    """FIFO 違規資訊"""
    current_pi: str
    current_date: str
    product: str
    customer: str
    earlier_orders: List[Dict[str, Any]]


class FIFOChecker:
    """FIFO 檢查器 - 檢查是否有更早的訂單未消完"""

    def __init__(self, executor):
        """
        Args:
            executor: SQL 查詢執行器（必須有 execute 方法）
        """
        self.executor = executor

    def check(self, pi_no: str, product: str, customer: str) -> Optional[FIFOViolation]:
        """
        檢查指定的訂單是否違反 FIFO 原則。

        Args:
            pi_no: PI 編號
            product: 產品代碼
            customer: 客戶代碼

        Returns:
            FIFOViolation 如果違規，None 如果正常
        """
        # Step 1: 取得當前訂單日期
        cursor = self.executor.execute(FIFOQueries.GET_ORDER_DATE, (pi_no,))
        row = cursor.fetchone()
        if not row:
            return None
        current_date = row[0]

        # Step 2: 查詢更早的訂單是否有剩餘
        cursor = self.executor.execute(
            FIFOQueries.GET_EARLIER_ORDERS_WITH_REMAINING,
            (customer, product, current_date)
        )
        earlier_orders = cursor.fetchall()

        if not earlier_orders:
            return None

        # 組裝違規資訊
        orders_list = []
        for order in earlier_orders:
            orders_list.append({
                'pi_no': order[0],
                'order_date': order[1],
                'remaining': order[4],
                'elapsed': format_elapsed_time(order[1])
            })

        return FIFOViolation(
            current_pi=pi_no,
            current_date=current_date,
            product=product,
            customer=customer,
            earlier_orders=orders_list
        )
