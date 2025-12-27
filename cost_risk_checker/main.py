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
