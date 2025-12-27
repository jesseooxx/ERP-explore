"""FIFO 監控系統 Demo - 不需要資料庫連線"""
import logging
from fifo_monitor.checker import FIFOViolation
from fifo_monitor.alert import show_alert

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def demo():
    """執行 Demo 模式 - 模擬 FIFO 違規警告"""
    logger.info("FIFO 監控系統 Demo 模式啟動...")
    logger.info("模擬偵測到新排程: PI=PI20241227001, 產品=PROD-A001, 客戶=CUST-001")

    # 建立模擬的違規資料
    violation = FIFOViolation(
        current_pi="PI20241227001",
        current_date="20241227",
        product="PROD-A001",
        customer="CUST-001",
        earlier_orders=[
            {
                'pi_no': 'PI20230615001',
                'order_date': '20230615',
                'remaining': 500,
                'elapsed': '1年6個月'
            },
            {
                'pi_no': 'PI20240301002',
                'order_date': '20240301',
                'remaining': 200,
                'elapsed': '9個月'
            },
            {
                'pi_no': 'PI20241101003',
                'order_date': '20241101',
                'remaining': 100,
                'elapsed': '1個月'
            },
        ]
    )

    logger.warning(f"⚠️ FIFO 違規! {len(violation.earlier_orders)} 張更早的訂單有剩餘")
    logger.info("顯示警告視窗...")

    # 顯示警告視窗
    show_alert(violation)

    logger.info("Demo 完成")


if __name__ == "__main__":
    demo()
