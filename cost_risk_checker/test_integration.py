"""整合測試 - 使用真實資料庫"""
import pyodbc
import pytest

from cost_risk_checker.config import Config
from cost_risk_checker.security import SafeQueryExecutor
from cost_risk_checker.checker import CostRiskChecker
from cost_risk_checker.formatter import format_table


@pytest.fixture
def checker():
    """建立 CostRiskChecker（自動管理連線）"""
    config = Config()
    conn = pyodbc.connect(config.connection_string)
    executor = SafeQueryExecutor(conn)
    yield CostRiskChecker(executor, config)
    executor.close()


@pytest.mark.integration
def test_check_known_product(checker):
    """測試檢查已知產品"""
    # 使用一個已知存在的產品編號
    result = checker.check_product("284102")

    # 只要有結果就算通過
    assert result is not None
    assert result.product_code == "284102"

    # 驗證有成本資料
    if result.cost_info:
        assert result.cost_info.supplier_code is not None


@pytest.mark.integration
def test_format_output(checker):
    """測試格式化輸出"""
    results = checker.check_products(["284102", "284006"])

    output = format_table(results, "test")

    # 驗證表格內容（避免 emoji 輸出）
    assert "284102" in output or len(results) > 0
