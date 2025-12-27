"""SQL 監控器 - 偵測 tfm03 新增記錄"""
from typing import List, Tuple, Set
from fifo_monitor.queries import FIFOQueries


class TFM03Monitor:
    """tfm03 表格監控器"""

    def __init__(self, executor):
        """
        Args:
            executor: SQL 查詢執行器
        """
        self.executor = executor
        self.last_count = 0
        self.known_records: Set[Tuple[str, str, str]] = set()  # (pi, product, schedule_date)

    def initialize(self):
        """初始化監控器，記錄當前狀態"""
        cursor = self.executor.execute(FIFOQueries.COUNT_TFM03)
        row = cursor.fetchone()
        self.last_count = row[0] if row else 0

        # 記錄當前最新的記錄
        cursor = self.executor.execute(FIFOQueries.GET_NEW_SCHEDULES)
        for row in cursor.fetchall():
            self.known_records.add((row[0], row[1], row[3]))  # pi, product, schedule_date

    def check_for_new_records(self) -> List[dict]:
        """
        檢查是否有新記錄。

        Returns:
            新記錄的列表，每筆包含 pi_no, product, customer
        """
        # 檢查記錄數是否增加
        cursor = self.executor.execute(FIFOQueries.COUNT_TFM03)
        row = cursor.fetchone()
        current_count = row[0] if row else 0

        if current_count <= self.last_count:
            return []

        # 有新記錄，取得最新的記錄
        self.last_count = current_count

        cursor = self.executor.execute(FIFOQueries.GET_NEW_SCHEDULES)
        new_records = []

        for row in cursor.fetchall():
            key = (row[0], row[1], row[3])  # pi, product, schedule_date
            if key not in self.known_records:
                self.known_records.add(key)
                new_records.append({
                    'pi_no': row[0],
                    'product': row[1],
                    'customer': row[2],
                })

        return new_records
