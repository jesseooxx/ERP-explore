"""
Test script for database connection module.

This script tests the database connection functionality and demonstrates
basic usage of the db module.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from db import DatabaseConnection, test_connection


def test_basic_connection():
    """Test basic database connection"""
    print("\n" + "=" * 60)
    print("Test 1: Basic Connection Test")
    print("=" * 60)

    success = test_connection()
    return success


def test_query_execution():
    """Test query execution with real ERP data"""
    print("\n" + "=" * 60)
    print("Test 2: Query Execution Test")
    print("=" * 60)

    try:
        with DatabaseConnection() as db:
            # Test 1: Count records in tfm01 (S/C master table)
            print("\nCounting records in tfm01 (S/C Master)...")
            count = db.execute_scalar("SELECT COUNT(*) FROM tfm01")
            print(f"Total records in tfm01: {count}")

            # Test 2: Get first 5 records from tfm01
            print("\nFetching first 5 records from tfm01...")
            results = db.execute_query("SELECT TOP 5 fa01, fa03, fa04, fa07 FROM tfm01")

            print(f"Retrieved {len(results)} records:")
            for idx, row in enumerate(results, 1):
                print(f"  {idx}. S/C No: {row.fa01}, Customer: {row.fa03}, Date: {row.fa04}")

            # Test 3: Query using dictionary format
            print("\nQuerying tfm01 with dictionary format...")
            dict_results = db.execute_dict("SELECT TOP 3 fa01, fa03, fa04 FROM tfm01")

            print(f"Retrieved {len(dict_results)} records as dictionaries:")
            for idx, record in enumerate(dict_results, 1):
                print(f"  {idx}. {record}")

            # Test 4: Get table structure
            print("\nGetting table structure for tfm01...")
            table_info = db.get_table_info("tfm01")

            print(f"Table tfm01 has {len(table_info)} columns:")
            for col in table_info[:5]:  # Show first 5 columns
                print(f"  - {col['COLUMN_NAME']}: {col['DATA_TYPE']}")

            return True

    except Exception as e:
        print(f"\nERROR: Query execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_parameterized_query():
    """Test parameterized queries for safety"""
    print("\n" + "=" * 60)
    print("Test 3: Parameterized Query Test")
    print("=" * 60)

    try:
        with DatabaseConnection() as db:
            # First, get a valid S/C number
            print("\nGetting a sample S/C number...")
            sample = db.execute_query("SELECT TOP 1 fa01 FROM tfm01")

            if sample:
                sc_no = sample[0].fa01
                print(f"Using S/C number: {sc_no}")

                # Test parameterized query
                print(f"\nQuerying for S/C {sc_no} using parameterized query...")
                results = db.execute_dict(
                    "SELECT fa01, fa03, fa04, fa07 FROM tfm01 WHERE fa01 = ?",
                    (sc_no,)
                )

                if results:
                    print(f"Found record: {results[0]}")
                else:
                    print("No records found")

                # Test with details table (tfm02)
                print(f"\nQuerying details for S/C {sc_no}...")
                details = db.execute_dict(
                    """
                    SELECT
                        fb01 AS sc_no,
                        fb02 AS item_no,
                        fb03 AS product_code,
                        fb06 AS product_name1,
                        fb09 AS quantity,
                        fb10 AS unit
                    FROM tfm02
                    WHERE fb01 = ?
                    ORDER BY fb02
                    """,
                    (sc_no,)
                )

                print(f"Found {len(details)} detail records:")
                for detail in details[:3]:  # Show first 3
                    print(f"  Item {detail['item_no']}: {detail['product_code']} - "
                          f"{detail['product_name1']} ({detail['quantity']} {detail['unit']})")

            return True

    except Exception as e:
        print(f"\nERROR: Parameterized query test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_table_existence():
    """Test if required ERP tables exist"""
    print("\n" + "=" * 60)
    print("Test 4: Table Existence Check")
    print("=" * 60)

    try:
        with DatabaseConnection() as db:
            required_tables = ['tfm01', 'tfm02', 'tqm01', 'tqm02']

            print("\nChecking for required ERP tables...")
            for table in required_tables:
                count = db.execute_scalar(
                    """
                    SELECT COUNT(*)
                    FROM INFORMATION_SCHEMA.TABLES
                    WHERE TABLE_NAME = ?
                    """,
                    (table,)
                )

                if count > 0:
                    # Get record count
                    rec_count = db.execute_scalar(f"SELECT COUNT(*) FROM {table}")
                    print(f"  [OK] {table} exists ({rec_count} records)")
                else:
                    print(f"  [NOT FOUND] {table}")

            return True

    except Exception as e:
        print(f"\nERROR: Table existence check failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print(" PI Generator - Database Connection Test Suite")
    print("=" * 80)

    tests = [
        ("Basic Connection", test_basic_connection),
        ("Query Execution", test_query_execution),
        ("Parameterized Queries", test_parameterized_query),
        ("Table Existence", test_table_existence),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\nUnexpected error in {test_name}: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 80)
    print(" Test Summary")
    print("=" * 80)

    for test_name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"  {status}: {test_name}")

    total_tests = len(results)
    passed_tests = sum(1 for _, success in results if success)

    print(f"\nTotal: {passed_tests}/{total_tests} tests passed")
    print("=" * 80 + "\n")

    return all(success for _, success in results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
