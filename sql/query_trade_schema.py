"""
Query trade-related table schemas from DATAWIN database
"""

import pyodbc

def get_connection():
    """Get database connection"""
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


class DatabaseConnection:
    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = get_connection()
        return self

    def __exit__(self, *args):
        if self.conn:
            self.conn.close()

    def test_connection(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            print("Database connection successful!")
            return True
        except:
            return False

    def execute_dict(self, sql, params=None):
        cursor = self.conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)

        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        cursor.close()
        return results

# Trade-related tables to query
TRADE_TABLES = [
    # Product tables
    'tdm01',  # Product Basic Data
    'tdm02',  # Product Sub_Description
    'tdm05',  # Product Assembly (BOM)
    'tdm09',  # Product Price Level

    # Supplier tables
    'tcm01',  # Supplier Basic Data
    'tcm05',  # Supplier Item

    # Quotation tables
    'tem01',  # Quotation Master
    'tem02',  # Quotation Item Data
    'tem05',  # Quotation/SC Item Assembly

    # Order (S/C) tables
    'tfm01',  # S/C Master
    'tfm02',  # S/C Item Data
]

def query_table_schema(db, table_name):
    """Query column information for a single table"""
    sql = """
        SELECT
            COLUMN_NAME,
            DATA_TYPE,
            CHARACTER_MAXIMUM_LENGTH,
            NUMERIC_PRECISION,
            IS_NULLABLE,
            ORDINAL_POSITION
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
    """
    return db.execute_dict(sql, (table_name,))

def query_sample_data(db, table_name, limit=3):
    """Query sample data from a table"""
    try:
        sql = f"SELECT TOP {limit} * FROM {table_name}"
        return db.execute_dict(sql)
    except Exception as e:
        print(f"  Error querying sample data: {e}")
        return []

def main():
    print("=" * 80)
    print("DATAWIN Trade Tables Schema Query")
    print("=" * 80)

    with DatabaseConnection() as db:
        if not db.test_connection():
            print("Database connection failed!")
            return

        for table_name in TRADE_TABLES:
            print(f"\n{'='*80}")
            print(f"TABLE: {table_name}")
            print("=" * 80)

            columns = query_table_schema(db, table_name)

            if not columns:
                print(f"  Table {table_name} not found or has no columns")
                continue

            print(f"\nColumns ({len(columns)} total):")
            print("-" * 70)
            print(f"{'Column':<15} {'Type':<15} {'Length':<10} {'Nullable':<10}")
            print("-" * 70)

            for col in columns:
                col_name = col['COLUMN_NAME']
                data_type = col['DATA_TYPE']
                max_len = col['CHARACTER_MAXIMUM_LENGTH'] or col.get('NUMERIC_PRECISION', '')
                nullable = col['IS_NULLABLE']

                print(f"{col_name:<15} {data_type:<15} {str(max_len):<10} {nullable:<10}")

            # Query sample data
            print(f"\nSample Data (first 3 rows):")
            print("-" * 70)
            samples = query_sample_data(db, table_name)

            if samples:
                for i, row in enumerate(samples):
                    print(f"\nRow {i+1}:")
                    for key, value in row.items():
                        if value is not None and str(value).strip():
                            print(f"  {key}: {value}")
            else:
                print("  No sample data available")

if __name__ == "__main__":
    main()
