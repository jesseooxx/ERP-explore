"""測試用 - 插入測試資料觸發 FIFO 監控"""
import pyodbc
from datetime import datetime
from fifo_monitor.config import Config


def trigger_test():
    """插入一筆測試排程記錄來觸發監控"""
    config = Config()

    conn_str = (
        f"DRIVER={{{config.db_driver}}};"
        f"SERVER={config.db_server};"
        f"DATABASE={config.db_name};"
        "Trusted_Connection=yes;"
    )

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    # 查詢現有記錄數
    cursor.execute("SELECT COUNT(*) FROM tfm03")
    before_count = cursor.fetchone()[0]
    print(f"插入前 tfm03 記錄數: {before_count}")

    # 插入測試記錄 (fc01 最多 10 字元，用 z 開頭確保在 TOP 20)
    today = datetime.now().strftime("%Y%m%d")
    test_pi = "zTEST001"  # z 開頭，排序最高
    test_product = "TEST-PROD"
    test_customer = "118"  # 使用現有客戶

    print(f"\n插入測試記錄:")
    print(f"  PI: {test_pi}")
    print(f"  產品: {test_product}")
    print(f"  客戶: {test_customer}")
    print(f"  日期: {today}")

    try:
        # 必填欄位：fc01, fc02, fc031, fc032, fc033, fc034, fc04, fc12, fc13, fc14, fc15
        cursor.execute("""
            INSERT INTO tfm03 (fc01, fc02, fc031, fc032, fc033, fc034, fc04, fc12, fc13, fc14, fc15, fc05, fc10)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (test_pi, today, 'TEST', '', '', '', test_product, '', '', '', '', 100, test_customer))
        conn.commit()
        print("\n[OK] 測試記錄已插入！監控程式應該會偵測到。")

        # 確認插入
        cursor.execute("SELECT COUNT(*) FROM tfm03")
        after_count = cursor.fetchone()[0]
        print(f"插入後 tfm03 記錄數: {after_count}")

        # 等待 10 秒讓監控偵測（監控每 3 秒檢查一次）
        print("\n等待 10 秒讓監控程式偵測...")
        import time
        time.sleep(10)

        # 清理測試資料（停用觸發器避免錯誤）
        print("\n清理測試資料...")
        cursor.execute("ALTER TABLE tfm03 DISABLE TRIGGER ALL")
        cursor.execute("DELETE FROM tfm03 WHERE fc01 = ?", (test_pi,))
        cursor.execute("ALTER TABLE tfm03 ENABLE TRIGGER ALL")
        conn.commit()
        print("[OK] 測試資料已清理")

    except Exception as e:
        print(f"\n[ERROR] 錯誤: {e}")
        conn.rollback()

    cursor.close()
    conn.close()


if __name__ == "__main__":
    trigger_test()
