"""
連線測試腳本

在部署前先執行此腳本，確認能連上公司 SQL Server

使用方式：
    # 設定環境變數後執行
    set FIFO_DB_SERVER=192.168.1.100
    python -m fifo_monitor.test_connection

    # 或用命令列參數
    python -m fifo_monitor.test_connection --server 192.168.1.100
"""
import argparse
import sys
import os

# 嘗試載入 .env 檔案（如果有安裝 python-dotenv）
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import pyodbc


def test_connection(server: str, database: str, auth_mode: str,
                    user: str = None, password: str = None) -> bool:
    """測試資料庫連線"""
    print("=" * 50)
    print("FIFO 監控系統 - 連線測試")
    print("=" * 50)
    print(f"\n伺服器: {server}")
    print(f"資料庫: {database}")
    print(f"驗證方式: {auth_mode}")

    # 建立連線字串
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={database};"
    )

    if auth_mode.lower() == "windows":
        conn_str += "Trusted_Connection=yes;"
        print("使用: Windows 驗證（網域帳號）")
    else:
        conn_str += f"UID={user};PWD={password};"
        print(f"使用: SQL 驗證（帳號: {user}）")

    print("\n嘗試連線中...")

    try:
        conn = pyodbc.connect(conn_str, timeout=10)
        cursor = conn.cursor()

        # 測試 1: 基本查詢
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        print(f"\n✓ 連線成功!")
        print(f"  SQL Server 版本: {version.split(chr(10))[0]}")

        # 測試 2: 確認 tfm01/tfm03 表存在
        print("\n檢查必要資料表...")
        for table in ['tfm01', 'tfm03']:
            cursor.execute(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
                f"WHERE TABLE_NAME = '{table}'"
            )
            exists = cursor.fetchone()[0] > 0
            if exists:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"  ✓ {table}: {count:,} 筆資料")
            else:
                print(f"  ✗ {table}: 不存在!")
                return False

        # 測試 3: 確認有讀取權限
        print("\n測試 FIFO 查詢...")
        cursor.execute("""
            SELECT TOP 1 a.fc02, a.fc03, a.fc04
            FROM tfm03 a
            JOIN tfm01 b ON a.fc02 = b.fc02
        """)
        row = cursor.fetchone()
        if row:
            print(f"  ✓ 查詢成功，可以讀取資料")
        else:
            print(f"  ⚠ 查詢成功但無資料（可能是空資料庫）")

        conn.close()
        print("\n" + "=" * 50)
        print("✓ 所有測試通過！可以啟動 FIFO 監控")
        print("=" * 50)
        return True

    except pyodbc.Error as e:
        print(f"\n✗ 連線失敗!")
        print(f"  錯誤: {e}")

        # 常見錯誤診斷
        error_str = str(e)
        if "Login failed" in error_str:
            print("\n診斷: 帳號或密碼錯誤")
            print("  - Windows 驗證: 確認你的網域帳號有資料庫存取權限")
            print("  - SQL 驗證: 確認帳號密碼正確")
        elif "Cannot open database" in error_str:
            print(f"\n診斷: 資料庫 '{database}' 不存在或無權限存取")
        elif "server was not found" in error_str or "TCP Provider" in error_str:
            print(f"\n診斷: 無法連線到伺服器 '{server}'")
            print("  - 確認伺服器名稱/IP 正確")
            print("  - 確認防火牆允許 SQL Server 連線（預設 port 1433）")
            print("  - 確認 SQL Server 服務正在運行")
        elif "ODBC Driver" in error_str:
            print("\n診斷: 缺少 ODBC 驅動程式")
            print("  下載: https://go.microsoft.com/fwlink/?linkid=2249004")

        return False


def main():
    parser = argparse.ArgumentParser(description="FIFO 監控連線測試")
    parser.add_argument("--server", "-s", help="SQL Server 位址")
    parser.add_argument("--database", "-d", default="DATAWIN", help="資料庫名稱")
    parser.add_argument("--auth", "-a", choices=["windows", "sql"],
                        help="驗證方式")
    parser.add_argument("--user", "-u", help="SQL 驗證帳號")
    parser.add_argument("--password", "-p", help="SQL 驗證密碼")
    args = parser.parse_args()

    # 優先使用命令列參數，其次環境變數
    server = args.server or os.getenv("FIFO_DB_SERVER")
    database = args.database or os.getenv("FIFO_DB_NAME", "DATAWIN")
    auth_mode = args.auth or os.getenv("FIFO_AUTH_MODE", "windows")
    user = args.user or os.getenv("FIFO_DB_USER")
    password = args.password or os.getenv("FIFO_DB_PASSWORD")

    if not server:
        print("錯誤: 請指定 SQL Server 位址")
        print("\n使用方式:")
        print("  python -m fifo_monitor.test_connection --server 192.168.1.100")
        print("  或")
        print("  set FIFO_DB_SERVER=192.168.1.100")
        print("  python -m fifo_monitor.test_connection")
        sys.exit(1)

    if auth_mode == "sql" and (not user or not password):
        print("錯誤: SQL 驗證需要 --user 和 --password")
        sys.exit(1)

    success = test_connection(server, database, auth_mode, user, password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
