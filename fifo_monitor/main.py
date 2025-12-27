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

        # 初始化監控器和檢查器（帶客戶過濾）
        monitor = TFM03Monitor(executor, customer_filter=config.customer_filter)
        checker = FIFOChecker(executor)

        monitor.initialize()
        logger.info("監控器初始化完成")
        if config.customer_filter:
            logger.info(f"📋 過濾客戶: {', '.join(config.customer_filter)}")
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
