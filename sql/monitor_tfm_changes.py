"""
TFM 資料表變化監控工具
用於觀察 ERP 系統寫入 tfm01/tfm02 的時機

使用方式：
1. 執行此腳本
2. 在 ERP 中操作 tfm 系統（新增/修改訂單）
3. 觀察這邊的輸出，了解資料是即時寫入還是最後才寫入
"""

import pyodbc
import time
from datetime import datetime

# 連線設定
CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=DATAWIN;"
    "Trusted_Connection=yes;"
)

def get_recent_records(cursor):
    """取得 tfm01 和 tfm02 最新的記錄數"""
    cursor.execute("SELECT COUNT(*) FROM tfm01")
    tfm01_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tfm02")
    tfm02_count = cursor.fetchone()[0]

    # 取得最新的 5 筆 tfm01
    cursor.execute("""
        SELECT TOP 5 fa01, fa03, fa04, fa08
        FROM tfm01
        ORDER BY fa01 DESC
    """)
    latest_tfm01 = cursor.fetchall()

    # 取得最新的 5 筆 tfm02
    cursor.execute("""
        SELECT TOP 5 fb01, fb02, fb03, fb09
        FROM tfm02
        ORDER BY fb01 DESC, fb02 DESC
    """)
    latest_tfm02 = cursor.fetchall()

    return tfm01_count, tfm02_count, latest_tfm01, latest_tfm02

def main():
    print("=" * 60)
    print("TFM 資料表變化監控工具")
    print("=" * 60)
    print("請在 ERP 中操作 tfm 系統，這裡會顯示資料變化")
    print("按 Ctrl+C 停止監控")
    print("-" * 60)

    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()

    # 取得初始狀態
    prev_tfm01_count, prev_tfm02_count, prev_tfm01, prev_tfm02 = get_recent_records(cursor)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 初始狀態:")
    print(f"  tfm01 (訂單主檔): {prev_tfm01_count} 筆")
    print(f"  tfm02 (訂單明細): {prev_tfm02_count} 筆")
    print("-" * 60)

    try:
        while True:
            time.sleep(1)  # 每秒檢查一次

            tfm01_count, tfm02_count, latest_tfm01, latest_tfm02 = get_recent_records(cursor)

            # 檢查 tfm01 變化
            if tfm01_count != prev_tfm01_count:
                diff = tfm01_count - prev_tfm01_count
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⚡ tfm01 變化: {diff:+d} 筆 (共 {tfm01_count} 筆)")
                print("  最新記錄:")
                for row in latest_tfm01[:3]:
                    print(f"    PI: {row[0]}, 日期: {row[1]}, 客戶: {row[2]}, 客戶單號: {row[3]}")
                prev_tfm01_count = tfm01_count

            # 檢查 tfm02 變化
            if tfm02_count != prev_tfm02_count:
                diff = tfm02_count - prev_tfm02_count
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⚡ tfm02 變化: {diff:+d} 筆 (共 {tfm02_count} 筆)")
                print("  最新記錄:")
                for row in latest_tfm02[:3]:
                    print(f"    PI: {row[0]}, 行號: {row[1]}, 產品: {row[2]}, 數量: {row[3]}")
                prev_tfm02_count = tfm02_count

    except KeyboardInterrupt:
        print("\n\n監控結束")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
