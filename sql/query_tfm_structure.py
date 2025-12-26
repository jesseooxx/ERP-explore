"""
Query tfm01 and tfm02 structures
"""

import pyodbc

def get_connection():
    conn_strings = [
        "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=DATAWIN;Trusted_Connection=yes;",
        "DRIVER={SQL Server};SERVER=localhost;DATABASE=DATAWIN;Trusted_Connection=yes;",
    ]
    for conn_str in conn_strings:
        try:
            return pyodbc.connect(conn_str, timeout=10)
        except:
            continue
    raise Exception("Could not connect to database")


def main():
    conn = get_connection()
    cursor = conn.cursor()

    print("=" * 80)
    print("tfm01 and tfm02 Structure Query")
    print("=" * 80)

    # Query tfm01 columns
    print("\n1. tfm01 (Order Master) columns:")
    cursor.execute("""
        SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'tfm01'
        ORDER BY ORDINAL_POSITION
    """)
    for row in cursor.fetchall():
        print(f"  {row.COLUMN_NAME}: {row.DATA_TYPE}({row.CHARACTER_MAXIMUM_LENGTH or ''})")

    # Query tfm02 columns
    print("\n2. tfm02 (Order Items) columns:")
    cursor.execute("""
        SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'tfm02'
        ORDER BY ORDINAL_POSITION
    """)
    for row in cursor.fetchall():
        print(f"  {row.COLUMN_NAME}: {row.DATA_TYPE}({row.CHARACTER_MAXIMUM_LENGTH or ''})")

    # Sample data from tfm01
    print("\n3. tfm01 sample data (first 3 rows):")
    cursor.execute("SELECT TOP 3 * FROM tfm01 ORDER BY fa03 DESC")
    columns = [col[0] for col in cursor.description]
    print(f"  Columns: {', '.join(columns[:15])}...")
    for row in cursor.fetchall():
        print("\n  Row:")
        for i, val in enumerate(row):
            if val is not None and str(val).strip():
                print(f"    {columns[i]}: {val}")

    # Sample data from tfm02
    print("\n4. tfm02 sample data (first 3 rows):")
    cursor.execute("SELECT TOP 3 * FROM tfm02 ORDER BY fb01 DESC")
    columns = [col[0] for col in cursor.description]
    print(f"  Columns: {', '.join(columns[:15])}...")
    for row in cursor.fetchall():
        print("\n  Row:")
        for i, val in enumerate(row):
            if val is not None and str(val).strip():
                print(f"    {columns[i]}: {val}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()
