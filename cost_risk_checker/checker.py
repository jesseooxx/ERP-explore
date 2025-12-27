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
