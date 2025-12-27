# FIFO 訂單監控系統 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 建立一個背景監控程式，當 ERP 系統新增排程時自動檢查 FIFO 違規並彈窗警告。

**Architecture:** Python 背景程式每 3 秒輪詢 SQL Server 的 tfm03 表格，偵測到新記錄時查詢同客戶+同產品是否有更早的訂單未消完，若有則顯示 Windows 彈窗警告。

**Tech Stack:** Python 3.x, pyodbc, tkinter (內建)

**Design Doc:** `docs/plans/2025-12-27-fifo-monitor-design.md`

---

## Task 1: 建立專案結構

**Files:**
- Create: `fifo_monitor/__init__.py`
- Create: `fifo_monitor/config.py`
- Create: `tests/__init__.py`
- Create: `tests/test_config.py`

**Step 1: 建立目錄結構**

```bash
mkdir -p fifo_monitor tests
```

**Step 2: 建立 `__init__.py` 檔案**

Create `fifo_monitor/__init__.py`:
```python
"""FIFO 訂單監控系統"""
__version__ = "0.1.0"
```

Create `tests/__init__.py`:
```python
"""FIFO Monitor Tests"""
```

**Step 3: 寫 config 的測試**

Create `tests/test_config.py`:
```python
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
```

**Step 4: 執行測試確認失敗**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'fifo_monitor.config'"

**Step 5: 實作 config.py**

Create `fifo_monitor/config.py`:
```python
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
```

**Step 6: 執行測試確認通過**

Run: `pytest tests/test_config.py -v`
Expected: PASS

**Step 7: Commit**

```bash
git add fifo_monitor/ tests/
git commit -m "feat(fifo): add project structure and config module"
```

---

## Task 2: 安全查詢執行器

**Files:**
- Create: `fifo_monitor/security.py`
- Create: `tests/test_security.py`

**Step 1: 寫安全檢查的測試**

Create `tests/test_security.py`:
```python
"""測試安全模組"""
import pytest
from fifo_monitor.security import SecurityError, validate_query


def test_select_query_allowed():
    """SELECT 查詢應該被允許"""
    query = "SELECT * FROM tfm01"
    validate_query(query)  # 不應拋出例外


def test_insert_query_blocked():
    """INSERT 查詢應該被阻擋"""
    query = "INSERT INTO tfm01 VALUES (1)"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_update_query_blocked():
    """UPDATE 查詢應該被阻擋"""
    query = "UPDATE tfm01 SET fa01 = 'x'"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_delete_query_blocked():
    """DELETE 查詢應該被阻擋"""
    query = "DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_drop_query_blocked():
    """DROP 查詢應該被阻擋"""
    query = "DROP TABLE tfm01"
    with pytest.raises(SecurityError, match="禁止"):
        validate_query(query)


def test_multi_statement_blocked():
    """多語句查詢應該被阻擋"""
    query = "SELECT * FROM tfm01; DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="多重語句"):
        validate_query(query)


def test_case_insensitive_blocking():
    """關鍵字檢查應不分大小寫"""
    query = "select * from tfm01; delete from tfm01"
    with pytest.raises(SecurityError):
        validate_query(query)


def test_non_select_start_blocked():
    """非 SELECT 開頭的查詢應被阻擋"""
    query = "WITH cte AS (SELECT 1) DELETE FROM tfm01"
    with pytest.raises(SecurityError, match="非 SELECT"):
        validate_query(query)
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_security.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: 實作 security.py**

Create `fifo_monitor/security.py`:
```python
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

    # 檢查 2：不能包含危險關鍵字
    for keyword in FORBIDDEN_KEYWORDS:
        pattern = r'\b' + keyword + r'\b'
        if re.search(pattern, normalized):
            raise SecurityError(f"禁止使用 {keyword}")

    # 檢查 3：不能有多重語句
    if ';' in query:
        raise SecurityError("禁止多重語句")
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_security.py -v`
Expected: PASS (8 tests)

**Step 5: Commit**

```bash
git add fifo_monitor/security.py tests/test_security.py
git commit -m "feat(fifo): add security module with query validation"
```

---

## Task 3: SQL 查詢白名單

**Files:**
- Create: `fifo_monitor/queries.py`
- Create: `tests/test_queries.py`

**Step 1: 寫查詢驗證的測試**

Create `tests/test_queries.py`:
```python
"""測試查詢模組"""
import pytest
from fifo_monitor.queries import FIFOQueries
from fifo_monitor.security import validate_query, SecurityError


def test_all_queries_are_safe():
    """所有預定義的查詢都應該通過安全檢查"""
    queries = [
        FIFOQueries.COUNT_TFM03,
        FIFOQueries.GET_NEW_SCHEDULES,
        FIFOQueries.GET_ORDER_DATE,
        FIFOQueries.GET_EARLIER_ORDERS_WITH_REMAINING,
    ]
    for query in queries:
        validate_query(query)  # 不應拋出例外


def test_queries_are_select_only():
    """所有查詢都應該是 SELECT"""
    queries = [
        FIFOQueries.COUNT_TFM03,
        FIFOQueries.GET_NEW_SCHEDULES,
        FIFOQueries.GET_ORDER_DATE,
        FIFOQueries.GET_EARLIER_ORDERS_WITH_REMAINING,
    ]
    for query in queries:
        assert query.strip().upper().startswith('SELECT')
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_queries.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: 實作 queries.py**

Create `fifo_monitor/queries.py`:
```python
"""SQL 查詢白名單 - 只有這些查詢可以被執行"""


class FIFOQueries:
    """FIFO 監控系統使用的 SQL 查詢"""

    # 計算 tfm03 記錄數
    COUNT_TFM03 = """
        SELECT COUNT(*) FROM tfm03
    """

    # 取得最新的排程記錄（用於偵測新增）
    GET_NEW_SCHEDULES = """
        SELECT TOP 20
            fc01 as pi_no,
            fc04 as product,
            fc10 as customer,
            fc02 as schedule_date,
            fc05 as scheduled_qty
        FROM tfm03
        ORDER BY fc01 DESC, fc02 DESC
    """

    # 取得訂單日期
    GET_ORDER_DATE = """
        SELECT fa03
        FROM tfm01
        WHERE fa01 = ?
    """

    # 查詢同客戶+同產品，更早的訂單是否有剩餘
    GET_EARLIER_ORDERS_WITH_REMAINING = """
        SELECT
            t1.fa01 as pi_no,
            t1.fa03 as order_date,
            SUM(t3.fc05) as total_scheduled,
            SUM(ISNULL(t3.fc06, 0)) as total_shipped,
            SUM(t3.fc05 - ISNULL(t3.fc06, 0)) as remaining
        FROM tfm01 t1
        INNER JOIN tfm03 t3 ON t3.fc01 = t1.fa01
        WHERE t3.fc10 = ?
          AND t3.fc04 = ?
          AND t1.fa03 < ?
        GROUP BY t1.fa01, t1.fa03
        HAVING SUM(t3.fc05 - ISNULL(t3.fc06, 0)) > 0
        ORDER BY t1.fa03 ASC
    """
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_queries.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fifo_monitor/queries.py tests/test_queries.py
git commit -m "feat(fifo): add SQL query whitelist"
```

---

## Task 4: 時間格式化工具

**Files:**
- Create: `fifo_monitor/utils.py`
- Create: `tests/test_utils.py`

**Step 1: 寫時間格式化的測試**

Create `tests/test_utils.py`:
```python
"""測試工具模組"""
import pytest
from datetime import date
from fifo_monitor.utils import format_elapsed_time


def test_format_years_and_months():
    """超過一年應顯示年和月"""
    # 假設今天是 2025-12-27，訂單日期是 2020-06-15
    order_date = "20200615"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "5年" in result
    assert "6個月" in result


def test_format_months_only():
    """不到一年應只顯示月"""
    order_date = "20250615"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "年" not in result
    assert "6個月" in result


def test_format_days_only():
    """不到一個月應只顯示天"""
    order_date = "20251215"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "年" not in result
    assert "月" not in result
    assert "12天" in result


def test_format_zero_days():
    """同一天應顯示 0 天"""
    order_date = "20251227"
    today = date(2025, 12, 27)
    result = format_elapsed_time(order_date, today)
    assert "0天" in result
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_utils.py -v`
Expected: FAIL

**Step 3: 實作 utils.py**

Create `fifo_monitor/utils.py`:
```python
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
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_utils.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fifo_monitor/utils.py tests/test_utils.py
git commit -m "feat(fifo): add time formatting utility"
```

---

## Task 5: FIFO 檢查器

**Files:**
- Create: `fifo_monitor/checker.py`
- Create: `tests/test_checker.py`

**Step 1: 寫 FIFO 檢查邏輯的測試（使用 Mock）**

Create `tests/test_checker.py`:
```python
"""測試 FIFO 檢查器"""
import pytest
from unittest.mock import Mock, MagicMock
from fifo_monitor.checker import FIFOChecker, FIFOViolation


def test_no_violation_when_no_earlier_orders():
    """沒有更早的訂單時不應報告違規"""
    mock_executor = Mock()
    mock_executor.execute.return_value = Mock(fetchone=Mock(return_value=('20241227',)))
    mock_executor.execute.return_value.fetchall = Mock(return_value=[])

    checker = FIFOChecker(mock_executor)
    result = checker.check('PI001', 'PROD001', 'CUST001')

    assert result is None


def test_violation_when_earlier_order_has_remaining():
    """有更早的訂單有剩餘時應報告違規"""
    mock_executor = Mock()

    # 模擬 GET_ORDER_DATE 返回
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [
        ('20241227',),  # 當前訂單日期
    ]
    mock_cursor.fetchall.return_value = [
        ('PI000', '20240101', 100, 50, 50),  # 更早的訂單有剩餘
    ]
    mock_executor.execute.return_value = mock_cursor

    checker = FIFOChecker(mock_executor)
    result = checker.check('PI001', 'PROD001', 'CUST001')

    assert result is not None
    assert isinstance(result, FIFOViolation)
    assert len(result.earlier_orders) == 1
    assert result.earlier_orders[0]['pi_no'] == 'PI000'
    assert result.earlier_orders[0]['remaining'] == 50
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_checker.py -v`
Expected: FAIL

**Step 3: 實作 checker.py**

Create `fifo_monitor/checker.py`:
```python
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
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_checker.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fifo_monitor/checker.py tests/test_checker.py
git commit -m "feat(fifo): add FIFO checker with violation detection"
```

---

## Task 6: 安全查詢執行器類別

**Files:**
- Modify: `fifo_monitor/security.py`
- Create: `tests/test_safe_executor.py`

**Step 1: 寫 SafeQueryExecutor 的測試**

Create `tests/test_safe_executor.py`:
```python
"""測試安全查詢執行器"""
import pytest
from unittest.mock import Mock, MagicMock
from fifo_monitor.security import SafeQueryExecutor, SecurityError


def test_executor_allows_select():
    """執行器應允許 SELECT 查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    executor.execute("SELECT * FROM tfm01")
    mock_conn.cursor().execute.assert_called()


def test_executor_blocks_delete():
    """執行器應阻擋 DELETE 查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    with pytest.raises(SecurityError):
        executor.execute("DELETE FROM tfm01")


def test_executor_with_params():
    """執行器應支援參數化查詢"""
    mock_conn = MagicMock()
    executor = SafeQueryExecutor(mock_conn)

    executor.execute("SELECT * FROM tfm01 WHERE fa01 = ?", ("PI001",))
    mock_conn.cursor().execute.assert_called_with(
        "SELECT * FROM tfm01 WHERE fa01 = ?", ("PI001",)
    )
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_safe_executor.py -v`
Expected: FAIL

**Step 3: 更新 security.py 加入 SafeQueryExecutor**

Append to `fifo_monitor/security.py`:
```python


class SafeQueryExecutor:
    """安全查詢執行器 - 只允許執行安全的 SELECT 查詢"""

    def __init__(self, connection):
        """
        Args:
            connection: pyodbc 連線物件
        """
        self.connection = connection
        self._cursor = None

    @property
    def cursor(self):
        if self._cursor is None:
            self._cursor = self.connection.cursor()
        return self._cursor

    def execute(self, query: str, params: tuple = None):
        """
        執行安全的 SQL 查詢。

        Args:
            query: SQL 查詢字串
            params: 查詢參數

        Returns:
            查詢結果 cursor

        Raises:
            SecurityError: 如果查詢不安全
        """
        validate_query(query)

        if params:
            return self.cursor.execute(query, params)
        return self.cursor.execute(query)

    def close(self):
        """關閉連線"""
        if self._cursor:
            self._cursor.close()
        self.connection.close()
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_safe_executor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fifo_monitor/security.py tests/test_safe_executor.py
git commit -m "feat(fifo): add SafeQueryExecutor class"
```

---

## Task 7: 警告視窗

**Files:**
- Create: `fifo_monitor/alert.py`

**Step 1: 實作警告視窗（UI 不易測試，直接實作）**

Create `fifo_monitor/alert.py`:
```python
"""警告視窗模組"""
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any


class FIFOAlertWindow:
    """FIFO 違規警告視窗"""

    def __init__(
        self,
        current_pi: str,
        current_date: str,
        product: str,
        earlier_orders: List[Dict[str, Any]]
    ):
        self.current_pi = current_pi
        self.current_date = current_date
        self.product = product
        self.earlier_orders = earlier_orders

        self.root = tk.Tk()
        self.root.title("⚠️ FIFO 訂單警告")
        self.root.geometry("550x400")
        self.root.resizable(False, False)

        # 置中顯示
        self.root.eval('tk::PlaceWindow . center')

        self._create_widgets()

    def _create_widgets(self):
        """建立視窗元件"""
        # 標題
        title_frame = tk.Frame(self.root, bg="#FFF3CD", padx=10, pady=10)
        title_frame.pack(fill=tk.X)

        tk.Label(
            title_frame,
            text="⚠️ FIFO 訂單警告",
            font=("Microsoft JhengHei", 14, "bold"),
            bg="#FFF3CD",
            fg="#856404"
        ).pack()

        # 當前訂單資訊
        current_frame = tk.LabelFrame(
            self.root,
            text="您正在處理的訂單",
            font=("Microsoft JhengHei", 10),
            padx=10, pady=5
        )
        current_frame.pack(fill=tk.X, padx=10, pady=10)

        # 格式化日期顯示
        formatted_date = f"{self.current_date[:4]}/{self.current_date[4:6]}/{self.current_date[6:]}"

        tk.Label(
            current_frame,
            text=f"PI: {self.current_pi}    日期: {formatted_date}    產品: {self.product}",
            font=("Consolas", 11)
        ).pack()

        # 警告訊息
        tk.Label(
            self.root,
            text="⚠️ 以下訂單還有剩餘數量，依 FIFO 應優先處理：",
            font=("Microsoft JhengHei", 10),
            fg="#DC3545"
        ).pack(pady=(10, 5))

        # 訂單清單（使用 Treeview）
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("pi_no", "order_date", "remaining", "elapsed")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)

        self.tree.heading("pi_no", text="PI 編號")
        self.tree.heading("order_date", text="訂單日期")
        self.tree.heading("remaining", text="剩餘數量")
        self.tree.heading("elapsed", text="已過時間")

        self.tree.column("pi_no", width=100)
        self.tree.column("order_date", width=100)
        self.tree.column("remaining", width=100, anchor=tk.E)
        self.tree.column("elapsed", width=100)

        # 插入資料
        for order in self.earlier_orders:
            formatted_date = f"{order['order_date'][:4]}/{order['order_date'][4:6]}/{order['order_date'][6:]}"
            self.tree.insert("", tk.END, values=(
                order['pi_no'],
                formatted_date,
                f"{order['remaining']:,.0f}",
                order['elapsed']
            ))

        # 捲軸
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 按鈕區
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=15)

        tk.Button(
            btn_frame,
            text="我知道了",
            command=self.root.destroy,
            width=12,
            font=("Microsoft JhengHei", 10)
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame,
            text="複製清單",
            command=self._copy_to_clipboard,
            width=12,
            font=("Microsoft JhengHei", 10)
        ).pack(side=tk.LEFT, padx=10)

    def _copy_to_clipboard(self):
        """複製清單到剪貼簿"""
        lines = [f"FIFO 警告 - PI: {self.current_pi}, 產品: {self.product}", ""]
        lines.append("應優先處理的訂單：")
        lines.append("-" * 50)

        for order in self.earlier_orders:
            formatted_date = f"{order['order_date'][:4]}/{order['order_date'][4:6]}/{order['order_date'][6:]}"
            lines.append(
                f"PI: {order['pi_no']:<12} "
                f"日期: {formatted_date}  "
                f"剩餘: {order['remaining']:>8,.0f}  "
                f"已過: {order['elapsed']}"
            )

        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

        # 顯示複製成功提示
        self.root.title("✓ 已複製到剪貼簿")
        self.root.after(2000, lambda: self.root.title("⚠️ FIFO 訂單警告"))

    def show(self):
        """顯示視窗"""
        # 置頂顯示
        self.root.attributes('-topmost', True)
        self.root.mainloop()


def show_alert(violation) -> None:
    """
    顯示 FIFO 違規警告。

    Args:
        violation: FIFOViolation 物件
    """
    window = FIFOAlertWindow(
        current_pi=violation.current_pi,
        current_date=violation.current_date,
        product=violation.product,
        earlier_orders=violation.earlier_orders
    )
    window.show()
```

**Step 2: Commit**

```bash
git add fifo_monitor/alert.py
git commit -m "feat(fifo): add alert window with tkinter"
```

---

## Task 8: SQL 監控器

**Files:**
- Create: `fifo_monitor/monitor.py`
- Create: `tests/test_monitor.py`

**Step 1: 寫監控器的測試**

Create `tests/test_monitor.py`:
```python
"""測試監控器"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from fifo_monitor.monitor import TFM03Monitor


def test_monitor_detects_new_records():
    """監控器應能偵測新記錄"""
    mock_executor = Mock()

    # 第一次查詢返回 100 筆
    # 第二次查詢返回 102 筆（新增 2 筆）
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [
        (100,),  # 初始計數
        (102,),  # 第二次計數
    ]
    mock_cursor.fetchall.return_value = [
        ('PI001', 'PROD001', 'CUST001', '20241227', 100),
        ('PI002', 'PROD002', 'CUST002', '20241227', 200),
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
```

**Step 2: 執行測試確認失敗**

Run: `pytest tests/test_monitor.py -v`
Expected: FAIL

**Step 3: 實作 monitor.py**

Create `fifo_monitor/monitor.py`:
```python
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
```

**Step 4: 執行測試確認通過**

Run: `pytest tests/test_monitor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fifo_monitor/monitor.py tests/test_monitor.py
git commit -m "feat(fifo): add tfm03 monitor for detecting new schedules"
```

---

## Task 9: 主程式

**Files:**
- Create: `fifo_monitor/main.py`

**Step 1: 實作主程式**

Create `fifo_monitor/main.py`:
```python
"""FIFO 監控主程式"""
import sys
import time
import logging
import pyodbc
from fifo_monitor.config import Config
from fifo_monitor.security import SafeQueryExecutor
from fifo_monitor.monitor import TFM03Monitor
from fifo_monitor.checker import FIFOChecker
from fifo_monitor.alert import show_alert


# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    """主程式入口"""
    config = Config()

    logger.info("FIFO 監控系統啟動中...")
    logger.info(f"連線至 {config.db_server}/{config.db_name}")

    try:
        # 建立連線
        conn = pyodbc.connect(config.connection_string)
        executor = SafeQueryExecutor(conn)

        # 初始化監控器和檢查器
        monitor = TFM03Monitor(executor)
        checker = FIFOChecker(executor)

        monitor.initialize()
        logger.info("監控器初始化完成")
        logger.info(f"開始監控 tfm03（每 {config.poll_interval} 秒檢查一次）")
        logger.info("按 Ctrl+C 停止監控")

        # 主迴圈
        while True:
            try:
                new_records = monitor.check_for_new_records()

                for record in new_records:
                    logger.info(
                        f"偵測到新排程: PI={record['pi_no']}, "
                        f"產品={record['product']}, 客戶={record['customer']}"
                    )

                    # 檢查 FIFO
                    violation = checker.check(
                        record['pi_no'],
                        record['product'],
                        record['customer']
                    )

                    if violation:
                        logger.warning(
                            f"⚠️ FIFO 違規! {len(violation.earlier_orders)} 張更早的訂單有剩餘"
                        )
                        show_alert(violation)
                    else:
                        logger.info("✓ FIFO 檢查通過")

                time.sleep(config.poll_interval)

            except pyodbc.Error as e:
                logger.error(f"資料庫錯誤: {e}")
                time.sleep(config.poll_interval)

    except KeyboardInterrupt:
        logger.info("\n監控已停止")
    except pyodbc.Error as e:
        logger.error(f"無法連線至資料庫: {e}")
        sys.exit(1)
    finally:
        if 'executor' in locals():
            executor.close()


if __name__ == "__main__":
    main()
```

**Step 2: Commit**

```bash
git add fifo_monitor/main.py
git commit -m "feat(fifo): add main entry point"
```

---

## Task 10: 執行測試與整合

**Step 1: 執行所有測試**

Run: `pytest tests/ -v`
Expected: All tests PASS

**Step 2: 測試程式可以啟動**

Run: `python -m fifo_monitor.main`
Expected: 程式啟動，顯示 "FIFO 監控系統啟動中..."

**Step 3: Final Commit**

```bash
git add -A
git commit -m "feat(fifo): complete FIFO order monitor system

- Config module for database settings
- Security module with query validation
- SQL query whitelist
- Time formatting utility
- FIFO checker with violation detection
- TFM03 monitor for new schedule detection
- Alert window with tkinter
- Main entry point with monitoring loop

Closes: FIFO order monitoring requirement"
```

---

## 後續：手動測試

由於你目前沒有連接到正式的 SQL Server，實際測試需要等到回到公司電腦。

**測試步驟：**
1. 確認可以連線到 SQL Server
2. 啟動監控程式
3. 在 ERP 中新增一筆排程
4. 確認程式偵測到新記錄並執行 FIFO 檢查
5. 如果有違規，確認彈窗正確顯示
