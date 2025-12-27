"""SQL 監控器 - 偵測 tfm03 新增記錄"""
from typing import List, Tuple, Set, Optional
from fifo_monitor.queries import FIFOQueries


class TFM03Monitor:
    """tfm03 表格監控器"""

    def __init__(self, executor, customer_filter: Optional[List[str]] = None):
        """
        Args:
            executor: SQL 查詢執行器
            customer_filter: 只監控這些客戶的訂單 (None = 監控全部)
        """
        self.executor = executor
        self.last_count = 0
        self.known_records: Set[Tuple[str, str, str]] = set()  # (pi, product, schedule_date)
        self.customer_filter = customer_filter or []

        # 預先建立過濾查詢
        if self.customer_filter:
            filter_str = FIFOQueries.build_customer_filter(self.customer_filter)
            self._count_query = FIFOQueries.COUNT_TFM03_FILTERED.format(customers=filter_str)
            self._schedules_query = FIFOQueries.GET_NEW_SCHEDULES_FILTERED.format(customers=filter_str)
            print(f"[Monitor] 只監控客戶: {', '.join(self.customer_filter)}")
        else:
            self._count_query = FIFOQueries.COUNT_TFM03
            self._schedules_query = FIFOQueries.GET_NEW_SCHEDULES
            print("[Monitor] 監控所有客戶")

    def initialize(self):
        """初始化監控器，記錄當前狀態"""
        cursor = self.executor.execute(self._count_query)
        row = cursor.fetchone()
        self.last_count = row[0] if row else 0

        # 記錄當前最新的記錄
        cursor = self.executor.execute(self._schedules_query)
        for row in cursor.fetchall():
            self.known_records.add((row[0], row[1], row[3]))  # pi, product, schedule_date

        print(f"[Monitor] 初始化完成，目前有 {self.last_count} 筆記錄")

    def check_for_new_records(self) -> List[dict]:
        """
        檢查是否有新記錄。

        Returns:
            新記錄的列表，每筆包含 pi_no, product, customer
        """
        # 檢查記錄數是否增加
        cursor = self.executor.execute(self._count_query)
        row = cursor.fetchone()
        current_count = row[0] if row else 0

        if current_count <= self.last_count:
            return []

        # 有新記錄，取得最新的記錄
        self.last_count = current_count

        cursor = self.executor.execute(self._schedules_query)
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
