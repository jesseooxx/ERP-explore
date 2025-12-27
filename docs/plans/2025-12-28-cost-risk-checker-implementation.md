# Cost Risk Checker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CLI tool that checks supplier cost staleness and purchase history for products, helping identify pricing risks before confirming customer orders.

**Architecture:** Modular Python tool following the same patterns as fifo_monitor. Separates concerns into queries, checker logic, and output formatting. Uses the existing SafeQueryExecutor pattern for database access.

**Tech Stack:** Python 3.x, pyodbc, dataclasses, argparse

---

## Task 1: Create Module Structure

**Files:**
- Create: `cost_risk_checker/__init__.py`
- Create: `cost_risk_checker/config.py`

**Step 1: Create module directory and init file**

```python
# cost_risk_checker/__init__.py
"""成本風險檢查工具 - 檢查供應商報價是否過時"""
__version__ = "1.0.0"
```

**Step 2: Create config file**

```python
# cost_risk_checker/config.py
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
```

**Step 3: Commit**

```bash
git add cost_risk_checker/
git commit -m "feat(cost-risk): create module structure with config"
```

---

## Task 2: Create SQL Queries Module

**Files:**
- Create: `cost_risk_checker/queries.py`

**Step 1: Create queries file with supplier cost query**

```python
# cost_risk_checker/queries.py
"""SQL 查詢 - 成本風險檢查使用的查詢"""


class CostRiskQueries:
    """成本風險檢查 SQL 查詢"""

    # 取得產品的最新供應商成本（按報價日期 ce07 最大）
    GET_LATEST_SUPPLIER_COST = """
        SELECT TOP 1
            ce011 as supplier_code,
            ce02 as product_code,
            ce06 as unit_cost,
            ce05 as currency,
            ce07 as quote_date
        FROM tcm05
        WHERE ce02 = ?
        ORDER BY ce07 DESC
    """

    # 取得產品的最後採購日期
    GET_LAST_PURCHASE_DATE = """
        SELECT TOP 1
            t1.ga03 as po_date,
            t1.ga01 as po_no
        FROM tgm01 t1
        INNER JOIN tgm02 t2 ON t2.gb01 = t1.ga01
        WHERE t2.gb03 = ?
        ORDER BY t1.ga03 DESC
    """

    # 取得供應商名稱
    GET_SUPPLIER_NAME = """
        SELECT ca02 as supplier_name
        FROM tcm01
        WHERE ca01 = ?
    """
```

**Step 2: Commit**

```bash
git add cost_risk_checker/queries.py
git commit -m "feat(cost-risk): add SQL queries for cost and purchase lookup"
```

---

## Task 3: Create Risk Assessment Logic

**Files:**
- Create: `cost_risk_checker/checker.py`
- Reference: `fifo_monitor/utils.py` (reuse format_elapsed_time)

**Step 1: Create checker with risk enum and data classes**

```python
# cost_risk_checker/checker.py
"""成本風險檢查器"""
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Optional, List

from cost_risk_checker.queries import CostRiskQueries


class RiskLevel(Enum):
    """風險等級"""
    HIGH = "high"      # 🔴 成本 > 2年 且 採購 > 1年
    MEDIUM = "medium"  # 🟡 成本 > 2年 但 採購 ≤ 1年
    LOW = "low"        # 🟢 成本 ≤ 2年


@dataclass
class CostInfo:
    """供應商成本資訊"""
    product_code: str
    supplier_code: str
    supplier_name: str
    unit_cost: float
    currency: str
    quote_date: str  # YYYYMMDD
    quote_age_months: int


@dataclass
class PurchaseInfo:
    """採購資訊"""
    last_po_date: Optional[str]  # YYYYMMDD or None
    last_po_no: Optional[str]
    purchase_age_months: Optional[int]  # None if never purchased


@dataclass
class ProductRiskResult:
    """產品風險評估結果"""
    product_code: str
    risk_level: RiskLevel
    cost_info: Optional[CostInfo]
    purchase_info: Optional[PurchaseInfo]
    recommendation: str


def calculate_months_ago(date_str: str, today: Optional[date] = None) -> int:
    """計算日期距今多少月"""
    if today is None:
        today = date.today()
    target_date = datetime.strptime(date_str, "%Y%m%d").date()
    delta_days = (today - target_date).days
    return delta_days // 30


def format_age(months: int) -> str:
    """格式化月數為 '年月' 格式"""
    if months >= 12:
        years = months // 12
        remaining_months = months % 12
        if remaining_months > 0:
            return f"{years}年{remaining_months}月"
        return f"{years}年"
    return f"{months}月"


class CostRiskChecker:
    """成本風險檢查器"""

    def __init__(self, executor, config):
        """
        Args:
            executor: SQL 查詢執行器
            config: 設定物件
        """
        self.executor = executor
        self.config = config

    def check_product(self, product_code: str) -> ProductRiskResult:
        """
        檢查單一產品的成本風險。

        Args:
            product_code: 產品代碼

        Returns:
            ProductRiskResult 風險評估結果
        """
        cost_info = self._get_cost_info(product_code)
        purchase_info = self._get_purchase_info(product_code)

        risk_level, recommendation = self._assess_risk(cost_info, purchase_info)

        return ProductRiskResult(
            product_code=product_code,
            risk_level=risk_level,
            cost_info=cost_info,
            purchase_info=purchase_info,
            recommendation=recommendation
        )

    def check_products(self, product_codes: List[str]) -> List[ProductRiskResult]:
        """批次檢查多個產品"""
        return [self.check_product(code) for code in product_codes]

    def _get_cost_info(self, product_code: str) -> Optional[CostInfo]:
        """取得產品的最新供應商成本"""
        cursor = self.executor.execute(
            CostRiskQueries.GET_LATEST_SUPPLIER_COST,
            (product_code,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        supplier_code = row[0]
        quote_date = row[4]
        quote_age = calculate_months_ago(quote_date)

        # 取得供應商名稱
        cursor = self.executor.execute(
            CostRiskQueries.GET_SUPPLIER_NAME,
            (supplier_code,)
        )
        name_row = cursor.fetchone()
        supplier_name = name_row[0] if name_row else supplier_code

        return CostInfo(
            product_code=product_code,
            supplier_code=supplier_code,
            supplier_name=supplier_name,
            unit_cost=row[2],
            currency=row[3],
            quote_date=quote_date,
            quote_age_months=quote_age
        )

    def _get_purchase_info(self, product_code: str) -> Optional[PurchaseInfo]:
        """取得產品的最後採購資訊"""
        cursor = self.executor.execute(
            CostRiskQueries.GET_LAST_PURCHASE_DATE,
            (product_code,)
        )
        row = cursor.fetchone()
        if not row:
            return PurchaseInfo(
                last_po_date=None,
                last_po_no=None,
                purchase_age_months=None
            )

        po_date = row[0]
        purchase_age = calculate_months_ago(po_date)

        return PurchaseInfo(
            last_po_date=po_date,
            last_po_no=row[1],
            purchase_age_months=purchase_age
        )

    def _assess_risk(
        self,
        cost_info: Optional[CostInfo],
        purchase_info: Optional[PurchaseInfo]
    ) -> tuple[RiskLevel, str]:
        """評估風險等級"""
        # 無成本資料
        if cost_info is None:
            return RiskLevel.HIGH, "無供應商成本資料"

        cost_stale = cost_info.quote_age_months > self.config.cost_stale_threshold_months

        # 判斷是否近期有採購
        if purchase_info and purchase_info.purchase_age_months is not None:
            purchase_recent = purchase_info.purchase_age_months <= self.config.purchase_recent_threshold_months
        else:
            purchase_recent = False

        if cost_stale and not purchase_recent:
            return RiskLevel.HIGH, "先問工廠"
        elif cost_stale and purchase_recent:
            return RiskLevel.MEDIUM, "留意"
        else:
            return RiskLevel.LOW, "-"
```

**Step 2: Commit**

```bash
git add cost_risk_checker/checker.py
git commit -m "feat(cost-risk): add risk assessment logic with HIGH/MEDIUM/LOW levels"
```

---

## Task 4: Create Output Formatter

**Files:**
- Create: `cost_risk_checker/formatter.py`

**Step 1: Create formatter with table and CSV output**

```python
# cost_risk_checker/formatter.py
"""輸出格式化"""
import csv
import io
from typing import List

from cost_risk_checker.checker import ProductRiskResult, RiskLevel, format_age


RISK_EMOJI = {
    RiskLevel.HIGH: "🔴",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🟢",
}


def format_table(results: List[ProductRiskResult], title: str = "") -> str:
    """
    格式化為 Markdown 表格。

    Args:
        results: 風險評估結果列表
        title: 報告標題

    Returns:
        Markdown 格式的表格字串
    """
    lines = []

    if title:
        lines.append(f"📋 成本風險檢查（{title}）")
        lines.append("")

    # 表頭
    lines.append("| 風險 | 產品編號 | 成本多久 | 採購多久 | 建議 | 工廠 | 成本報價日 | 最後採購日 |")
    lines.append("|------|----------|---------|---------|------|------|-----------|-----------|")

    # 統計
    high_count = 0
    medium_count = 0
    low_count = 0

    # 按風險等級排序（高風險在前）
    sorted_results = sorted(results, key=lambda r: (
        0 if r.risk_level == RiskLevel.HIGH else
        1 if r.risk_level == RiskLevel.MEDIUM else 2
    ))

    for r in sorted_results:
        emoji = RISK_EMOJI.get(r.risk_level, "❓")

        # 成本多久
        if r.cost_info:
            cost_age = format_age(r.cost_info.quote_age_months)
            quote_date = f"{r.cost_info.quote_date[:4]}-{r.cost_info.quote_date[4:6]}"
            supplier = r.cost_info.supplier_code
        else:
            cost_age = "無資料"
            quote_date = "-"
            supplier = "-"

        # 採購多久
        if r.purchase_info and r.purchase_info.purchase_age_months is not None:
            purchase_age = format_age(r.purchase_info.purchase_age_months)
            po_date = f"{r.purchase_info.last_po_date[:4]}-{r.purchase_info.last_po_date[4:6]}"
        else:
            purchase_age = "無紀錄"
            po_date = "-"

        lines.append(
            f"| {emoji} | {r.product_code} | {cost_age} | {purchase_age} | "
            f"{r.recommendation} | {supplier} | {quote_date} | {po_date} |"
        )

        # 統計
        if r.risk_level == RiskLevel.HIGH:
            high_count += 1
        elif r.risk_level == RiskLevel.MEDIUM:
            medium_count += 1
        else:
            low_count += 1

    # 摘要
    lines.append("")
    warnings = []
    if high_count > 0:
        warnings.append(f"{high_count} 個高風險")
    if medium_count > 0:
        warnings.append(f"{medium_count} 個中風險")

    if warnings:
        lines.append(f"⚠️ {', '.join(warnings)}，建議回簽前確認")
    else:
        lines.append("✅ 所有品項風險低")

    return "\n".join(lines)


def format_csv(results: List[ProductRiskResult]) -> str:
    """
    格式化為 CSV。

    Args:
        results: 風險評估結果列表

    Returns:
        CSV 格式字串
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # 標頭
    writer.writerow([
        "風險等級", "產品編號", "成本月數", "採購月數",
        "建議", "工廠", "成本報價日", "最後採購日"
    ])

    for r in results:
        risk = r.risk_level.value

        if r.cost_info:
            cost_months = r.cost_info.quote_age_months
            quote_date = r.cost_info.quote_date
            supplier = r.cost_info.supplier_code
        else:
            cost_months = ""
            quote_date = ""
            supplier = ""

        if r.purchase_info and r.purchase_info.purchase_age_months is not None:
            purchase_months = r.purchase_info.purchase_age_months
            po_date = r.purchase_info.last_po_date
        else:
            purchase_months = ""
            po_date = ""

        writer.writerow([
            risk, r.product_code, cost_months, purchase_months,
            r.recommendation, supplier, quote_date, po_date
        ])

    return output.getvalue()
```

**Step 2: Commit**

```bash
git add cost_risk_checker/formatter.py
git commit -m "feat(cost-risk): add table and CSV output formatters"
```

---

## Task 5: Create CLI Entry Point

**Files:**
- Create: `cost_risk_checker/main.py`
- Copy from: `fifo_monitor/security.py` (SafeQueryExecutor)

**Step 1: Copy security module**

```bash
cp fifo_monitor/security.py cost_risk_checker/security.py
```

**Step 2: Create main CLI**

```python
# cost_risk_checker/main.py
"""CLI 入口點"""
import argparse
import sys
import pyodbc

from cost_risk_checker.config import Config
from cost_risk_checker.security import SafeQueryExecutor
from cost_risk_checker.checker import CostRiskChecker
from cost_risk_checker.formatter import format_table, format_csv


def main():
    parser = argparse.ArgumentParser(
        description="檢查產品成本風險 - 找出報價過時的品項"
    )
    parser.add_argument(
        "products",
        nargs="*",
        help="產品編號（可輸入多個）"
    )
    parser.add_argument(
        "--file", "-f",
        help="從檔案讀取產品編號（每行一個）"
    )
    parser.add_argument(
        "--csv",
        metavar="OUTPUT",
        help="輸出 CSV 到指定檔案"
    )
    parser.add_argument(
        "--threshold-years",
        type=int,
        default=2,
        help="成本過時門檻（年），預設 2"
    )
    parser.add_argument(
        "--title",
        default="",
        help="報告標題（例如訂單編號）"
    )

    args = parser.parse_args()

    # 收集產品編號
    product_codes = list(args.products)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                code = line.strip()
                if code and not code.startswith("#"):
                    product_codes.append(code)

    if not product_codes:
        parser.print_help()
        sys.exit(1)

    # 去重複
    product_codes = list(dict.fromkeys(product_codes))

    # 設定
    config = Config()
    config.cost_stale_threshold_months = args.threshold_years * 12

    # 連線資料庫
    try:
        conn = pyodbc.connect(config.connection_string)
    except Exception as e:
        print(f"❌ 資料庫連線失敗: {e}", file=sys.stderr)
        sys.exit(1)

    executor = SafeQueryExecutor(conn)

    try:
        # 執行檢查
        checker = CostRiskChecker(executor, config)
        results = checker.check_products(product_codes)

        # 輸出
        print(format_table(results, args.title))

        if args.csv:
            with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
                f.write(format_csv(results))
            print(f"\n📄 CSV 已儲存至 {args.csv}")

    finally:
        executor.close()


if __name__ == "__main__":
    main()
```

**Step 3: Commit**

```bash
git add cost_risk_checker/main.py cost_risk_checker/security.py
git commit -m "feat(cost-risk): add CLI entry point with CSV export"
```

---

## Task 6: Create Tests

**Files:**
- Create: `cost_risk_checker/test_checker.py`

**Step 1: Create unit tests**

```python
# cost_risk_checker/test_checker.py
"""成本風險檢查器測試"""
import pytest
from datetime import date
from unittest.mock import Mock, MagicMock

from cost_risk_checker.checker import (
    CostRiskChecker,
    RiskLevel,
    calculate_months_ago,
    format_age,
)
from cost_risk_checker.config import Config


class TestCalculateMonthsAgo:
    """測試月份計算"""

    def test_same_month(self):
        today = date(2025, 12, 28)
        result = calculate_months_ago("20251215", today)
        assert result == 0

    def test_six_months_ago(self):
        today = date(2025, 12, 28)
        result = calculate_months_ago("20250615", today)
        assert result == 6

    def test_two_years_ago(self):
        today = date(2025, 12, 28)
        result = calculate_months_ago("20231228", today)
        assert result == 24


class TestFormatAge:
    """測試年月格式化"""

    def test_months_only(self):
        assert format_age(6) == "6月"

    def test_one_year(self):
        assert format_age(12) == "1年"

    def test_years_and_months(self):
        assert format_age(27) == "2年3月"


class TestCostRiskChecker:
    """測試風險評估邏輯"""

    def setup_method(self):
        self.config = Config()
        self.config.cost_stale_threshold_months = 24  # 2 年
        self.config.purchase_recent_threshold_months = 12  # 1 年

    def _create_mock_executor(self, cost_data, purchase_data, supplier_name="Test Supplier"):
        """建立 mock executor"""
        executor = Mock()
        cursor = MagicMock()
        executor.execute.return_value = cursor

        # 設定 fetchone 回傳值序列
        cursor.fetchone.side_effect = [
            cost_data,      # GET_LATEST_SUPPLIER_COST
            (supplier_name,) if cost_data else None,  # GET_SUPPLIER_NAME
            purchase_data,  # GET_LAST_PURCHASE_DATE
        ]

        return executor

    def test_high_risk_old_cost_old_purchase(self):
        """成本舊 + 採購舊 = 高風險"""
        # 成本 3 年前，採購 2 年前
        cost_data = ("S001", "P001", 100.0, "NT$", "20221228")
        purchase_data = ("20231228", "PO001")

        executor = self._create_mock_executor(cost_data, purchase_data)
        checker = CostRiskChecker(executor, self.config)

        # Mock 今天日期
        result = checker.check_product("P001")

        assert result.risk_level == RiskLevel.HIGH
        assert result.recommendation == "先問工廠"

    def test_medium_risk_old_cost_recent_purchase(self):
        """成本舊 + 採購近期 = 中風險"""
        # 成本 3 年前，採購 6 個月前
        cost_data = ("S001", "P001", 100.0, "NT$", "20221228")
        purchase_data = ("20250628", "PO001")

        executor = self._create_mock_executor(cost_data, purchase_data)
        checker = CostRiskChecker(executor, self.config)

        result = checker.check_product("P001")

        assert result.risk_level == RiskLevel.MEDIUM
        assert result.recommendation == "留意"

    def test_low_risk_recent_cost(self):
        """成本新 = 低風險"""
        # 成本 6 個月前
        cost_data = ("S001", "P001", 100.0, "NT$", "20250628")
        purchase_data = None

        executor = self._create_mock_executor(cost_data, purchase_data)
        checker = CostRiskChecker(executor, self.config)

        result = checker.check_product("P001")

        assert result.risk_level == RiskLevel.LOW
        assert result.recommendation == "-"

    def test_high_risk_no_cost_data(self):
        """無成本資料 = 高風險"""
        executor = self._create_mock_executor(None, None)
        checker = CostRiskChecker(executor, self.config)

        result = checker.check_product("P001")

        assert result.risk_level == RiskLevel.HIGH
        assert "無供應商成本資料" in result.recommendation
```

**Step 2: Run tests**

```bash
cd C:\Code_Projects\ERP-explore
python -m pytest cost_risk_checker/test_checker.py -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add cost_risk_checker/test_checker.py
git commit -m "test(cost-risk): add unit tests for risk assessment logic"
```

---

## Task 7: Integration Test with Real Database

**Files:**
- Create: `cost_risk_checker/test_integration.py`

**Step 1: Create integration test**

```python
# cost_risk_checker/test_integration.py
"""整合測試 - 使用真實資料庫"""
import pyodbc
import pytest

from cost_risk_checker.config import Config
from cost_risk_checker.security import SafeQueryExecutor
from cost_risk_checker.checker import CostRiskChecker
from cost_risk_checker.formatter import format_table


@pytest.fixture
def db_connection():
    """建立資料庫連線"""
    config = Config()
    try:
        conn = pyodbc.connect(config.connection_string)
        yield conn
    finally:
        conn.close()


@pytest.mark.integration
def test_check_known_product(db_connection):
    """測試檢查已知產品"""
    config = Config()
    executor = SafeQueryExecutor(db_connection)

    try:
        checker = CostRiskChecker(executor, config)
        # 使用一個已知存在的產品編號
        result = checker.check_product("284102")

        print(f"\n產品: {result.product_code}")
        print(f"風險: {result.risk_level}")
        if result.cost_info:
            print(f"成本: {result.cost_info.unit_cost} {result.cost_info.currency}")
            print(f"報價日: {result.cost_info.quote_date}")
            print(f"供應商: {result.cost_info.supplier_code}")
        if result.purchase_info:
            print(f"最後採購: {result.purchase_info.last_po_date}")

        # 只要有結果就算通過
        assert result is not None

    finally:
        executor.close()


@pytest.mark.integration
def test_format_output(db_connection):
    """測試格式化輸出"""
    config = Config()
    executor = SafeQueryExecutor(db_connection)

    try:
        checker = CostRiskChecker(executor, config)
        results = checker.check_products(["284102", "284006"])

        output = format_table(results, "測試報告")
        print(f"\n{output}")

        assert "產品編號" in output
        assert "風險" in output

    finally:
        executor.close()
```

**Step 2: Run integration test**

```bash
python -m pytest cost_risk_checker/test_integration.py -v -m integration
```

**Step 3: Commit**

```bash
git add cost_risk_checker/test_integration.py
git commit -m "test(cost-risk): add integration test with real database"
```

---

## Task 8: Final Polish and Documentation

**Files:**
- Create: `cost_risk_checker/README.md`

**Step 1: Create README**

```markdown
# 成本風險檢查工具

檢查供應商報價是否過時，幫助在回簽客戶訂單前識別價格風險。

## 安裝

確保已安裝相依套件：

```bash
pip install pyodbc
```

## 使用方式

### 基本使用

```bash
# 檢查單一產品
python -m cost_risk_checker.main 284102

# 檢查多個產品
python -m cost_risk_checker.main 284102 284006 310052

# 從檔案讀取
python -m cost_risk_checker.main --file products.txt
```

### 輸出 CSV

```bash
python -m cost_risk_checker.main 284102 284006 --csv output.csv
```

### 調整門檻

```bash
# 成本超過 3 年才視為過時（預設 2 年）
python -m cost_risk_checker.main 284102 --threshold-years 3
```

### 加上標題

```bash
python -m cost_risk_checker.main 284102 --title "PO-2024-12345"
```

## 風險等級說明

| 等級 | 條件 | 建議 |
|------|------|------|
| 🔴 高風險 | 成本 > 2年 且 採購 > 1年 | 回簽前先問工廠 |
| 🟡 中風險 | 成本 > 2年 但 採購 ≤ 1年 | 留意，但工廠較難漲價 |
| 🟢 低風險 | 成本 ≤ 2年 | 正常 |

## 與 Claude Code 整合

1. 將客戶 PDF 訂單丟給 Claude
2. Claude 抽取產品編號
3. Claude 呼叫此工具檢查
4. 回傳風險報告
```

**Step 2: Commit**

```bash
git add cost_risk_checker/README.md
git commit -m "docs(cost-risk): add README with usage instructions"
```

---

## Summary

**Total Tasks:** 8
**Estimated Time:** 60-90 minutes

**Files Created:**
- `cost_risk_checker/__init__.py`
- `cost_risk_checker/config.py`
- `cost_risk_checker/queries.py`
- `cost_risk_checker/checker.py`
- `cost_risk_checker/formatter.py`
- `cost_risk_checker/main.py`
- `cost_risk_checker/security.py` (copied)
- `cost_risk_checker/test_checker.py`
- `cost_risk_checker/test_integration.py`
- `cost_risk_checker/README.md`

**Key Dependencies:**
- pyodbc (existing)
- pytest (existing)
