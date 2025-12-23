"""
Example usage of the database connection module.

This script demonstrates how to use the db module to query ERP data.
"""

from db import DatabaseConnection


def example_basic_query():
    """Example 1: Basic query execution"""
    print("\n" + "=" * 60)
    print("Example 1: Basic Query")
    print("=" * 60)

    with DatabaseConnection() as db:
        # Simple query
        results = db.execute_query("SELECT TOP 5 fa01, fa07 FROM tfm01")

        print("First 5 S/C records:")
        for row in results:
            print(f"  S/C No: {row.fa01}, Customer: {row.fa07}")


def example_parameterized_query():
    """Example 2: Parameterized query (safe from SQL injection)"""
    print("\n" + "=" * 60)
    print("Example 2: Parameterized Query")
    print("=" * 60)

    with DatabaseConnection() as db:
        # Get a sample S/C number
        sample = db.execute_query("SELECT TOP 1 fa01 FROM tfm01 WHERE fa01 LIKE '%-%'")

        if sample:
            sc_no = sample[0].fa01
            print(f"\nQuerying S/C: {sc_no}")

            # Query master record
            master = db.execute_dict(
                "SELECT fa01, fa03, fa07, fa08 FROM tfm01 WHERE fa01 = ?",
                (sc_no,)
            )

            if master:
                print(f"Customer: {master[0]['fa07']}")
                print(f"PO No: {master[0]['fa08']}")

            # Query detail records
            details = db.execute_dict(
                """
                SELECT
                    fb02 AS item_no,
                    fb03 AS product_code,
                    fb06 AS product_name,
                    fb09 AS quantity,
                    fb10 AS unit
                FROM tfm02
                WHERE fb01 = ?
                ORDER BY fb02
                """,
                (sc_no,)
            )

            print(f"\nFound {len(details)} items:")
            for detail in details:
                print(f"  {detail['item_no']}: {detail['product_code']} - "
                      f"{detail['product_name']} ({detail['quantity']} {detail['unit']})")


def example_scalar_query():
    """Example 3: Get a single value"""
    print("\n" + "=" * 60)
    print("Example 3: Scalar Query")
    print("=" * 60)

    with DatabaseConnection() as db:
        # Get counts
        sc_count = db.execute_scalar("SELECT COUNT(*) FROM tfm01")
        item_count = db.execute_scalar("SELECT COUNT(*) FROM tfm02")

        print(f"Total S/C records: {sc_count}")
        print(f"Total item records: {item_count}")
        print(f"Average items per S/C: {item_count / sc_count:.2f}")


def example_table_info():
    """Example 4: Get table structure information"""
    print("\n" + "=" * 60)
    print("Example 4: Table Information")
    print("=" * 60)

    with DatabaseConnection() as db:
        # Get tfm01 structure
        columns = db.get_table_info("tfm01")

        print(f"\ntfm01 table structure ({len(columns)} columns):")
        print("\nFirst 10 columns:")
        for col in columns[:10]:
            nullable = "NULL" if col['IS_NULLABLE'] == 'YES' else "NOT NULL"
            max_len = f"({col['CHARACTER_MAXIMUM_LENGTH']})" if col['CHARACTER_MAXIMUM_LENGTH'] else ""
            print(f"  {col['COLUMN_NAME']}: {col['DATA_TYPE']}{max_len} {nullable}")


def example_complex_join():
    """Example 5: Complex join query"""
    print("\n" + "=" * 60)
    print("Example 5: Join Query (Master + Details)")
    print("=" * 60)

    with DatabaseConnection() as db:
        # Join master and details
        results = db.execute_dict(
            """
            SELECT TOP 10
                m.fa01 AS sc_no,
                m.fa07 AS customer,
                d.fb02 AS item_no,
                d.fb03 AS product_code,
                d.fb09 AS quantity
            FROM tfm01 m
            INNER JOIN tfm02 d ON m.fa01 = d.fb01
            WHERE m.fa01 LIKE '%-%'
            ORDER BY m.fa01, d.fb02
            """
        )

        print(f"\nFound {len(results)} joined records:")
        current_sc = None
        for row in results:
            if row['sc_no'] != current_sc:
                current_sc = row['sc_no']
                print(f"\nS/C {current_sc} - {row['customer']}")

            print(f"  Item {row['item_no']}: {row['product_code']} ({row['quantity']})")


def main():
    """Run all examples"""
    print("\n" + "=" * 80)
    print(" PI Generator - Database Module Usage Examples")
    print("=" * 80)

    examples = [
        example_basic_query,
        example_parameterized_query,
        example_scalar_query,
        example_table_info,
        example_complex_join,
    ]

    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"\nError running {example.__name__}: {e}")

    print("\n" + "=" * 80)
    print(" All examples completed!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
