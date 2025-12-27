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
