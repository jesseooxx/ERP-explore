"""
FIFO 監控主程式 - 生產環境版本

使用方式：
    # 1. 設定環境變數
    set FIFO_DB_SERVER=192.168.1.100

    # 2. 執行
    python -m fifo_monitor.main_production
"""
import sys
import time
import logging
import os

# 載入 .env 檔案
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import pyodbc
from fifo_monitor.config_production import ProductionConfig
from fifo_monitor.security import SafeQueryExecutor
from fifo_monitor.monitor import TFM03Monitor
from fifo_monitor.checker import FIFOChecker
from fifo_monitor.alert import show_alert


# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    """主程式入口 - 生產環境"""
    config = ProductionConfig()

    # 驗證設定
    try:
        config.validate()
    except ValueError as e:
        logger.error(f"設定錯誤: {e}")
        sys.exit(1)

    logger.info("=" * 50)
    logger.info("FIFO 監控系統 - 生產環境")
    logger.info("=" * 50)
    logger.info(f"\n{config}")
    logger.info("")

    try:
        # 建立連線
        logger.info("正在連線至資料庫...")
        conn = pyodbc.connect(config.connection_string, timeout=30)
        logger.info("✓ 連線成功")

        executor = SafeQueryExecutor(conn)

        # 初始化監控器和檢查器
        monitor = TFM03Monitor(executor, customer_filter=config.customer_filter)
        checker = FIFOChecker(executor)

        monitor.initialize()
        logger.info("✓ 監控器初始化完成")

        if config.customer_filter:
            logger.info(f"客戶過濾: {', '.join(config.customer_filter)}")
        else:
            logger.info("監控範圍: 所有客戶")

        logger.info(f"輪詢間隔: {config.poll_interval} 秒")
        logger.info("-" * 50)
        logger.info("監控中... 按 Ctrl+C 停止")
        logger.info("")

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
                logger.info(f"將在 {config.poll_interval} 秒後重試...")
                time.sleep(config.poll_interval)

    except KeyboardInterrupt:
        logger.info("\n監控已停止")
    except pyodbc.Error as e:
        logger.error(f"無法連線至資料庫: {e}")
        sys.exit(1)
    finally:
        if 'executor' in locals():
            executor.close()
            logger.info("資料庫連線已關閉")


if __name__ == "__main__":
    main()
