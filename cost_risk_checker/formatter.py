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
            supplier = r.cost_info.supplier_name  # 顯示名稱而非代碼
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
            supplier = r.cost_info.supplier_name  # 顯示名稱而非代碼
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
