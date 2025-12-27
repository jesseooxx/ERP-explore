"""測試 FIFO 違規警告 - 插入會觸發違規的資料"""
import pyodbc
import time
import threading
from fifo_monitor.config import Config
from fifo_monitor.security import SafeQueryExecutor
from fifo_monitor.monitor import TFM03Monitor
from fifo_monitor.checker import FIFOChecker
from fifo_monitor.alert import show_alert


def run_test():
    """執行 FIFO 違規測試"""
    config = Config()

    # 寫入用連線（不用 ReadOnly）
    write_conn_str = (
        f"DRIVER={{{config.db_driver}}};"
        f"SERVER={config.db_server};"
        f"DATABASE={config.db_name};"
        "Trusted_Connection=yes;"
    )

    # 監控用連線
    monitor_conn = pyodbc.connect(config.connection_string)
    executor = SafeQueryExecutor(monitor_conn)

    # 初始化監控器和檢查器
    monitor = TFM03Monitor(executor)
    checker = FIFOChecker(executor)
    monitor.initialize()

    print("監控器已初始化")
    print()

    # 測試資料：使用 pcn15301（日期 2010/03/21），配合客戶 498 + 產品 UF711002
    # 這會觸發 FIFO 違規，因為有 2007 年的訂單（710312）還有剩餘數量
    test_pi = 'pcn15301'
    test_product = 'UF711002'
    test_customer = '498'
    today = '20251227'

    print("插入測試資料...")
    print(f"  PI: {test_pi} (訂單日期: 2010/03/21)")
    print(f"  產品: {test_product}")
    print(f"  客戶: {test_customer}")
    print()
    print("預期結果：FIFO 違規")
    print("  - 訂單 710312 (2007/11/01) 同客戶+產品還有剩餘數量")
    print()

    # 插入測試資料
    write_conn = pyodbc.connect(write_conn_str)
    write_cursor = write_conn.cursor()

    try:
        write_cursor.execute('''
            INSERT INTO tfm03 (fc01, fc02, fc031, fc032, fc033, fc034, fc04, fc12, fc13, fc14, fc15, fc05, fc10)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (test_pi, today, 'TEST', '', '', '', test_product, '', '', '', '', 100, test_customer))
        write_conn.commit()
        print("[OK] 測試記錄已插入")
        print()

        # 等待一下讓資料庫同步
        time.sleep(1)

        # 檢查新記錄
        print("檢查新記錄...")
        new_records = monitor.check_for_new_records()

        if new_records:
            print(f"[OK] 偵測到 {len(new_records)} 筆新記錄")
            for record in new_records:
                print(f"     PI={record['pi_no']}, 產品={record['product']}, 客戶={record['customer']}")

                # 檢查 FIFO
                print()
                print("執行 FIFO 檢查...")
                violation = checker.check(
                    record['pi_no'],
                    record['product'],
                    record['customer']
                )

                if violation:
                    print(f"[VIOLATION] FIFO 違規! {len(violation.earlier_orders)} 張更早的訂單有剩餘")
                    for order in violation.earlier_orders:
                        print(f"     PI={order['pi_no']}, 日期={order['order_date']}, 剩餘={order['remaining']}")
                    print()
                    print("顯示警告視窗...")
                    show_alert(violation)
                else:
                    print("[OK] FIFO 檢查通過（無違規）")
        else:
            print("[WARN] 沒有偵測到新記錄")

    except Exception as e:
        print(f"[ERROR] {e}")
        write_conn.rollback()

    finally:
        # 清理測試資料
        print()
        print("清理測試資料...")
        try:
            write_cursor.execute('ALTER TABLE tfm03 DISABLE TRIGGER ALL')
            write_cursor.execute('DELETE FROM tfm03 WHERE fc01 = ? AND fc04 = ? AND fc10 = ? AND fc02 = ?',
                               (test_pi, test_product, test_customer, today))
            write_cursor.execute('ALTER TABLE tfm03 ENABLE TRIGGER ALL')
            write_conn.commit()
            print("[OK] 已清理")
        except Exception as e:
            print(f"[WARN] 清理失敗: {e}")

        write_cursor.close()
        write_conn.close()
        executor.close()


if __name__ == "__main__":
    run_test()
