"""測試用 - 插入測試資料到 tfm03 來觸發 FIFO 監控"""
import pyodbc
from fifo_monitor.config import Config


def insert_test_schedule():
    """插入一筆測試排程記錄"""
    config = Config()

    # 移除 ReadOnly 限制，允許寫入
    conn_str = (
        f"DRIVER={{{config.db_driver}}};"
        f"SERVER={config.db_server};"
        f"DATABASE={config.db_name};"
        "Trusted_Connection=yes;"
    )

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    # 先查詢現有的 tfm03 記錄，找一個可以參考的 PI
    print("查詢現有 tfm03 記錄...")
    cursor.execute("SELECT TOP 5 fc01, fc04, fc10, fc02, fc05 FROM tfm03 ORDER BY fc01 DESC")
    rows = cursor.fetchall()

    if not rows:
        print("tfm03 沒有資料，無法測試")
        return

    print("\n最新的 5 筆排程：")
    print("-" * 60)
    for row in rows:
        print(f"PI: {row[0]}, 產品: {row[1]}, 客戶: {row[2]}, 日期: {row[3]}, 數量: {row[4]}")

    # 使用第一筆的資料來建立測試記錄
    ref_pi = rows[0][0]
    ref_product = rows[0][1]
    ref_customer = rows[0][2]

    print(f"\n準備插入測試記錄（參考 PI={ref_pi}）...")
    print("注意：這只是查詢，不會實際插入資料")
    print("\n如果要真正插入測試資料，請在 SSMS 執行以下 SQL：")
    print("-" * 60)
    print(f"""
INSERT INTO tfm03 (fc01, fc02, fc04, fc05, fc10)
VALUES ('{ref_pi}', CONVERT(varchar, GETDATE(), 112), '{ref_product}', 100, '{ref_customer}')
""")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    insert_test_schedule()
