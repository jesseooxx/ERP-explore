"""
Test script for PI Data Query Module

This script tests the pi_data module by querying actual PI data from the database.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pi_generator.pi_data import (
    get_pi_data,
    list_recent_sc_numbers,
    PIDataQueryError
)
from pi_generator.db import DatabaseConnection


def test_list_recent_sc():
    """Test listing recent S/C numbers"""
    print("\n" + "=" * 70)
    print("TEST 1: List Recent S/C Numbers")
    print("=" * 70)

    try:
        sc_numbers = list_recent_sc_numbers(10)

        if sc_numbers:
            print(f"\nFound {len(sc_numbers)} recent S/C numbers:")
            for i, sc_no in enumerate(sc_numbers, 1):
                print(f"  {i:2d}. {sc_no}")
            return sc_numbers
        else:
            print("\nNo S/C numbers found!")
            return []

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return []


def test_get_pi_data(sc_no: str):
    """Test getting complete PI data"""
    print("\n" + "=" * 70)
    print(f"TEST 2: Get PI Data for {sc_no}")
    print("=" * 70)

    try:
        pi_data = get_pi_data(sc_no)

        # Display summary
        print("\n" + "-" * 70)
        print("PI DATA SUMMARY")
        print("-" * 70)
        print(str(pi_data))

        # Display master
        print("\n" + "-" * 70)
        print("MASTER DATA (tfm01)")
        print("-" * 70)
        print(f"  S/C Number:      {pi_data.master.sc_no}")
        print(f"  Create Date:     {pi_data.master.formatted_date} (raw: {pi_data.master.create_date})")
        print(f"  Customer Code:   {pi_data.master.customer_code}")
        print(f"  Customer PO:     {pi_data.master.customer_po}")
        print(f"  Trade Terms:     {pi_data.master.trade_terms}")
        print(f"  Payment Terms:   {pi_data.master.payment_terms}")
        print(f"  Total Amount:    ${pi_data.master.total_amount:,.2f}")

        # Display customer
        print("\n" + "-" * 70)
        print("CUSTOMER DATA (tbm01)")
        print("-" * 70)
        print(f"  Code:            {pi_data.customer.code}")
        print(f"  Name:            {pi_data.customer.name}")
        print(f"  Short Name:      {pi_data.customer.short_name}")
        print(f"  Address:         {pi_data.customer.address[:100]}...")

        # Display details
        print("\n" + "-" * 70)
        print(f"DETAIL DATA (tfm02) - {pi_data.item_count} items")
        print("-" * 70)

        total_check = 0.0
        for detail in pi_data.details:
            print(f"\n  Item {detail.item_seq}:")
            print(f"    Product Code:  {detail.product_code}")
            print(f"    Product Name:  {detail.full_product_name}")
            print(f"    Quantity:      {detail.quantity:,.2f} {detail.unit}")
            print(f"    Unit Price:    ${detail.unit_price:,.4f}")
            print(f"    Amount:        ${detail.amount:,.2f}")
            total_check += detail.amount

        # Validation
        print("\n" + "-" * 70)
        print("VALIDATION")
        print("-" * 70)
        print(f"  Master Total:      ${pi_data.master.total_amount:,.2f}")
        print(f"  Calculated Total:  ${pi_data.calculated_total:,.2f}")
        print(f"  Manual Total:      ${total_check:,.2f}")
        print(f"  Difference:        ${abs(pi_data.master.total_amount - pi_data.calculated_total):,.2f}")
        print(f"  Is Valid:          {pi_data.is_valid}")

        if pi_data.is_valid:
            print("\n  [OK] PI data is VALID")
        else:
            print("\n  [FAIL] PI data is INVALID")

        return True

    except PIDataQueryError as e:
        print(f"\nPIDataQueryError: {e}")
        return False
    except Exception as e:
        print(f"\nUnexpected Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multiple_sc_numbers(sc_numbers: list):
    """Test multiple S/C numbers"""
    print("\n" + "=" * 70)
    print("TEST 3: Test Multiple S/C Numbers")
    print("=" * 70)

    results = []
    for sc_no in sc_numbers[:3]:  # Test first 3
        print(f"\nTesting {sc_no}...")
        try:
            pi_data = get_pi_data(sc_no)
            print(f"  [OK] Success - {pi_data.item_count} items, ${pi_data.master.total_amount:,.2f}")
            results.append((sc_no, True, None))
        except Exception as e:
            print(f"  [FAIL] Failed - {e}")
            results.append((sc_no, False, str(e)))

    # Summary
    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    success_count = sum(1 for _, success, _ in results if success)
    print(f"  Total:    {len(results)}")
    print(f"  Success:  {success_count}")
    print(f"  Failed:   {len(results) - success_count}")

    return results


def test_error_handling():
    """Test error handling"""
    print("\n" + "=" * 70)
    print("TEST 4: Error Handling")
    print("=" * 70)

    # Test non-existent S/C
    print("\nTest 4.1: Non-existent S/C number")
    try:
        pi_data = get_pi_data("INVALID_SC_99999")
        print("  [FAIL] Should have raised PIDataQueryError")
    except PIDataQueryError as e:
        print(f"  [OK] Correctly raised PIDataQueryError: {e}")
    except Exception as e:
        print(f"  [FAIL] Unexpected error: {e}")

    # Test empty S/C
    print("\nTest 4.2: Empty S/C number")
    try:
        pi_data = get_pi_data("")
        print("  [FAIL] Should have raised PIDataQueryError")
    except PIDataQueryError as e:
        print(f"  [OK] Correctly raised PIDataQueryError: {e}")
    except Exception as e:
        print(f"  [FAIL] Unexpected error: {e}")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("PI DATA MODULE - COMPREHENSIVE TEST SUITE")
    print("=" * 70)

    # Test 1: List S/C numbers
    sc_numbers = test_list_recent_sc()

    if not sc_numbers:
        print("\n[FAIL] Cannot continue tests - no S/C numbers found")
        return False

    # Test 2: Get detailed PI data for first S/C
    test_sc_no = sc_numbers[0]
    success = test_get_pi_data(test_sc_no)

    if not success:
        print(f"\n[FAIL] Failed to get PI data for {test_sc_no}")
        return False

    # Test 3: Test multiple S/C numbers
    if len(sc_numbers) > 1:
        test_multiple_sc_numbers(sc_numbers)

    # Test 4: Error handling
    test_error_handling()

    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETED")
    print("=" * 70 + "\n")

    return True


if __name__ == "__main__":
    # Run all tests
    success = run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)
