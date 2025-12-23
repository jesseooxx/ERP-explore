"""
Test script for PI File Manager module.

This script tests all file management functionality including:
- Filename generation
- Filepath generation
- Directory creation
- File saving
- File listing
- Edge cases and error handling
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from pi_generator import (
    get_pi_data,
    get_pi_filename,
    get_pi_filepath,
    save_pi_pdf,
    ensure_directory_exists,
    get_customer_directory,
    list_pi_files,
    sanitize_filename,
    validate_pi_data_for_filing,
    generate_pi_pdf_bytes,
    FileManagerError
)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_subsection(title):
    """Print a subsection header"""
    print("\n" + "-" * 70)
    print(title)
    print("-" * 70)


def test_sanitize_filename():
    """Test filename sanitization"""
    print_subsection("Test 1: Filename Sanitization")

    test_cases = [
        ("PI_ T25C22 (506046).pdf", "PI_ T25C22 (506046).pdf"),
        ("PI_ T/25C22 (506*046).pdf", "PI_ T_25C22 (506_046).pdf"),
        ('PI_ T<25>C22 ("test").pdf', "PI_ T_25_C22 (_test_).pdf"),
        ("  PI_ T25C22 (506046).pdf  ", "PI_ T25C22 (506046).pdf"),
    ]

    all_passed = True
    for input_name, expected in test_cases:
        result = sanitize_filename(input_name)
        passed = result == expected
        all_passed = all_passed and passed
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] '{input_name}' -> '{result}'")
        if not passed:
            print(f"         Expected: '{expected}'")

    return all_passed


def test_filename_generation(pi_data):
    """Test filename generation"""
    print_subsection("Test 2: Filename Generation")

    try:
        filename = get_pi_filename(pi_data)
        print(f"  Generated filename: {filename}")

        # Check format
        expected_pattern = f"PI_ {pi_data.master.sc_no} ({pi_data.master.customer_po}).pdf"
        if filename == expected_pattern:
            print(f"  [PASS] Filename matches expected pattern")
            return True
        else:
            print(f"  [FAIL] Expected: {expected_pattern}")
            return False

    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_filepath_generation(pi_data):
    """Test filepath generation"""
    print_subsection("Test 3: Filepath Generation")

    try:
        # Test production path
        prod_path = get_pi_filepath(pi_data)
        print(f"  Production path: {prod_path}")

        expected_prod = f"Z:\\LEILA\\PI\\{pi_data.customer.code}\\PI_ {pi_data.master.sc_no} ({pi_data.master.customer_po}).pdf"
        prod_ok = prod_path == expected_prod

        # Test custom base directory
        test_path = get_pi_filepath(pi_data, base_dir="output")
        print(f"  Test path:       {test_path}")

        expected_test = f"output\\{pi_data.customer.code}\\PI_ {pi_data.master.sc_no} ({pi_data.master.customer_po}).pdf"
        test_ok = test_path == expected_test

        if prod_ok and test_ok:
            print(f"  [PASS] All paths generated correctly")
            return True
        else:
            if not prod_ok:
                print(f"  [FAIL] Production path incorrect")
                print(f"         Expected: {expected_prod}")
            if not test_ok:
                print(f"  [FAIL] Test path incorrect")
                print(f"         Expected: {expected_test}")
            return False

    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_directory_creation(pi_data):
    """Test directory creation"""
    print_subsection("Test 4: Directory Creation")

    try:
        # Create test directory
        customer_dir = get_customer_directory(pi_data.customer.code, base_dir="output")
        print(f"  Customer directory: {customer_dir}")

        ensure_directory_exists(customer_dir)

        if os.path.exists(customer_dir) and os.path.isdir(customer_dir):
            print(f"  [PASS] Directory created successfully")
            return True
        else:
            print(f"  [FAIL] Directory was not created")
            return False

    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_file_saving(pi_data):
    """Test PDF file saving"""
    print_subsection("Test 5: File Saving")

    try:
        # Generate actual PDF
        print("  Generating PDF bytes...")
        pdf_bytes = generate_pi_pdf_bytes(pi_data)
        print(f"  PDF size: {len(pdf_bytes):,} bytes")

        # Save to test location
        print("  Saving PDF...")
        saved_path = save_pi_pdf(pi_data, pdf_bytes, base_dir="output")
        print(f"  Saved to: {saved_path}")

        # Verify file exists
        if os.path.exists(saved_path):
            file_size = os.path.getsize(saved_path)
            print(f"  File exists: Yes")
            print(f"  File size: {file_size:,} bytes")

            if file_size == len(pdf_bytes):
                print(f"  [PASS] File saved correctly")
                return True
            else:
                print(f"  [FAIL] File size mismatch")
                return False
        else:
            print(f"  [FAIL] File was not created")
            return False

    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_listing(pi_data):
    """Test file listing"""
    print_subsection("Test 6: File Listing")

    try:
        files = list_pi_files(pi_data.customer.code, base_dir="output")
        print(f"  Found {len(files)} file(s) for customer {pi_data.customer.code}:")

        for f in files:
            file_size = os.path.getsize(f)
            print(f"    - {os.path.basename(f)} ({file_size:,} bytes)")

        if len(files) > 0:
            print(f"  [PASS] File listing successful")
            return True
        else:
            print(f"  [WARN] No files found (might be OK if this is first run)")
            return True

    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_validation():
    """Test validation of PIData"""
    print_subsection("Test 7: PIData Validation")

    from pi_generator.pi_data import PIData, PIMaster, PICustomer, PIDetail

    # Test invalid data
    test_cases = [
        ("Missing customer code", PIData(
            master=PIMaster("T25C22", "20250101", "", "PO123", "FOB", "NET 30", 1000.0),
            customer=PICustomer("", "Test", "TST", "Address"),
            details=[PIDetail("T25C22", 1, "P001", "Product", "", 10, "PCS", 100, 1000)]
        )),
        ("Missing S/C number", PIData(
            master=PIMaster("", "20250101", "604", "PO123", "FOB", "NET 30", 1000.0),
            customer=PICustomer("604", "Test", "TST", "Address"),
            details=[PIDetail("", 1, "P001", "Product", "", 10, "PCS", 100, 1000)]
        )),
        ("Missing customer PO", PIData(
            master=PIMaster("T25C22", "20250101", "604", "", "FOB", "NET 30", 1000.0),
            customer=PICustomer("604", "Test", "TST", "Address"),
            details=[PIDetail("T25C22", 1, "P001", "Product", "", 10, "PCS", 100, 1000)]
        )),
    ]

    all_passed = True
    for description, invalid_data in test_cases:
        try:
            validate_pi_data_for_filing(invalid_data)
            print(f"  [FAIL] {description}: Should have raised error")
            all_passed = False
        except FileManagerError as e:
            print(f"  [PASS] {description}: Correctly rejected ({str(e)[:50]}...)")

    return all_passed


def test_edge_cases():
    """Test edge cases"""
    print_subsection("Test 8: Edge Cases")

    all_passed = True

    # Test empty PDF bytes
    from pi_generator.pi_data import PIData, PIMaster, PICustomer, PIDetail
    valid_data = PIData(
        master=PIMaster("T25C22", "20250101", "604", "PO123", "FOB", "NET 30", 1000.0),
        customer=PICustomer("604", "Test", "TST", "Address"),
        details=[PIDetail("T25C22", 1, "P001", "Product", "", 10, "PCS", 100, 1000)]
    )

    try:
        save_pi_pdf(valid_data, b"", base_dir="output")
        print(f"  [FAIL] Empty PDF bytes: Should have raised error")
        all_passed = False
    except FileManagerError:
        print(f"  [PASS] Empty PDF bytes: Correctly rejected")

    # Test wrong type for PDF bytes
    try:
        save_pi_pdf(valid_data, "not bytes", base_dir="output")
        print(f"  [FAIL] Wrong type: Should have raised error")
        all_passed = False
    except FileManagerError:
        print(f"  [PASS] Wrong type: Correctly rejected")

    return all_passed


def main():
    """Main test function"""
    print_section("PI FILE MANAGER - COMPREHENSIVE TEST SUITE")

    # Get test S/C number
    if len(sys.argv) > 1:
        test_sc_no = sys.argv[1]
    else:
        # Try to get a recent S/C number
        from pi_generator import list_recent_sc_numbers
        recent = list_recent_sc_numbers(5)
        if recent:
            test_sc_no = recent[0]
            print(f"\nUsing recent S/C number: {test_sc_no}")
        else:
            test_sc_no = "T25C22"
            print(f"\nUsing default S/C number: {test_sc_no}")

    # Load PI data
    print_section("Loading Test Data")
    try:
        pi_data = get_pi_data(test_sc_no)
        print(f"S/C Number:   {pi_data.master.sc_no}")
        print(f"Customer:     {pi_data.customer.code} - {pi_data.customer.name}")
        print(f"Customer PO:  {pi_data.master.customer_po}")
        print(f"Items:        {pi_data.item_count}")
        print(f"Total:        ${pi_data.master.total_amount:,.2f}")
    except Exception as e:
        print(f"\n[ERROR] Failed to load PI data: {e}")
        return 1

    # Run all tests
    results = []

    print_section("Running Tests")

    results.append(("Filename Sanitization", test_sanitize_filename()))
    results.append(("Filename Generation", test_filename_generation(pi_data)))
    results.append(("Filepath Generation", test_filepath_generation(pi_data)))
    results.append(("Directory Creation", test_directory_creation(pi_data)))
    results.append(("File Saving", test_file_saving(pi_data)))
    results.append(("File Listing", test_file_listing(pi_data)))
    results.append(("PIData Validation", test_validation()))
    results.append(("Edge Cases", test_edge_cases()))

    # Print summary
    print_section("TEST SUMMARY")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "[+]" if result else "[X]"
        print(f"  {symbol} {test_name:.<50} {status}")

    print(f"\n  Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n  SUCCESS: ALL TESTS PASSED!")
        print_section("")
        return 0
    else:
        print(f"\n  WARNING: {total - passed} test(s) failed")
        print_section("")
        return 1


if __name__ == "__main__":
    sys.exit(main())
