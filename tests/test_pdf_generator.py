"""
Unit tests for PDF Generator module

Tests the PDF generation functionality including:
- Utility functions (currency extraction, date formatting, number-to-words)
- PDF generation with valid and invalid data
- Error handling
- File output and bytes generation
"""

import unittest
from pathlib import Path
import tempfile
import os
from datetime import datetime

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from pi_generator.pdf_generator import (
    PDFGenerationError,
    extract_currency_symbol,
    amount_to_words,
    format_date_invoice,
    format_quantity,
    format_currency,
    generate_pi_pdf_bytes,
    generate_pi_pdf
)
from pi_generator.pi_data import PIData, PIMaster, PIDetail, PICustomer


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""

    def test_extract_currency_symbol_usd(self):
        """Test USD currency extraction"""
        self.assertEqual(extract_currency_symbol("FOB SHANGHAI USD"), "US$")
        self.assertEqual(extract_currency_symbol("FOB TAIWAN US$"), "US$")
        self.assertEqual(extract_currency_symbol("fob shanghai usd"), "US$")

    def test_extract_currency_symbol_eur(self):
        """Test EUR currency extraction"""
        self.assertEqual(extract_currency_symbol("CIF HAMBURG EUR"), "EUR")

    def test_extract_currency_symbol_default(self):
        """Test default currency when none specified"""
        self.assertEqual(extract_currency_symbol("FOB TAIWAN"), "US$")
        self.assertEqual(extract_currency_symbol(""), "US$")
        self.assertEqual(extract_currency_symbol(None), "US$")

    def test_amount_to_words_simple(self):
        """Test simple amount conversion"""
        result = amount_to_words(100.00, "US$")
        self.assertIn("ONE HUNDRED", result)
        self.assertIn("DOLLARS", result)
        self.assertIn("00/100", result)

    def test_amount_to_words_with_cents(self):
        """Test amount with cents"""
        result = amount_to_words(123.45, "US$")
        self.assertIn("ONE HUNDRED", result)
        self.assertIn("TWENTY-THREE", result)
        self.assertIn("45/100", result)

    def test_amount_to_words_zero(self):
        """Test zero amount"""
        result = amount_to_words(0.00, "US$")
        self.assertIn("ZERO", result)

    def test_amount_to_words_large(self):
        """Test large amount"""
        result = amount_to_words(12480.00, "US$")
        self.assertIn("TWELVE THOUSAND", result)
        self.assertIn("FOUR HUNDRED", result)
        self.assertIn("EIGHTY", result)

    def test_format_date_invoice(self):
        """Test date formatting"""
        self.assertEqual(format_date_invoice("2025-12-23"), "DEC. 23, 2025")
        self.assertEqual(format_date_invoice("2025-01-01"), "JAN. 1, 2025")

    def test_format_date_invoice_invalid(self):
        """Test invalid date formatting"""
        # Should return original string if parsing fails
        result = format_date_invoice("invalid-date")
        self.assertEqual(result, "invalid-date")

    def test_format_quantity_whole_number(self):
        """Test quantity formatting with whole number"""
        self.assertEqual(format_quantity(6000.0, "PCS"), "6,000 PCS")
        self.assertEqual(format_quantity(1.0, "SET"), "1 SET")

    def test_format_quantity_decimal(self):
        """Test quantity formatting with decimal"""
        self.assertEqual(format_quantity(1234.56, "KG"), "1,234.56 KG")

    def test_format_currency(self):
        """Test currency formatting"""
        self.assertEqual(format_currency(12480.00, "US$"), "US$ 12,480.00")
        self.assertEqual(format_currency(1234.56, "EUR"), "EUR 1,234.56")


class TestPDFGeneration(unittest.TestCase):
    """Test PDF generation functions"""

    def setUp(self):
        """Set up test data"""
        # Create sample PI data
        self.master = PIMaster(
            sc_no="T25C99",
            create_date="20251223",
            customer_code="TEST01",
            customer_po="PO-2025-TEST",
            trade_terms="FOB TAIWAN USD",
            payment_terms="T/T 30 DAYS",
            total_amount=24960.00
        )

        self.customer = PICustomer(
            code="TEST01",
            name="TEST CUSTOMER COMPANY LTD.",
            short_name="TEST CUSTOMER",
            address="123 TEST STREET\nTEST CITY, TEST STATE 12345\nTEST COUNTRY"
        )

        self.details = [
            PIDetail(
                sc_no="T25C99",
                item_seq=1,
                product_code="PROD-001",
                product_name_1="Test Product Name Line 1",
                product_name_2="Test Product Description Line 2",
                quantity=6000.0,
                unit="PCS",
                unit_price=2.08,
                amount=12480.00
            ),
            PIDetail(
                sc_no="T25C99",
                item_seq=2,
                product_code="PROD-002",
                product_name_1="Another Test Product",
                product_name_2="With Additional Description",
                quantity=3000.0,
                unit="PCS",
                unit_price=4.16,
                amount=12480.00
            )
        ]

        self.pi_data = PIData(
            master=self.master,
            details=self.details,
            customer=self.customer
        )

    def test_generate_pdf_bytes_success(self):
        """Test successful PDF generation as bytes"""
        pdf_bytes = generate_pi_pdf_bytes(self.pi_data)

        # Check that PDF was generated
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 0)

        # Check PDF signature (PDF files start with %PDF)
        self.assertTrue(pdf_bytes.startswith(b'%PDF'))

    def test_generate_pdf_bytes_none_data(self):
        """Test PDF generation with None data"""
        with self.assertRaises(PDFGenerationError) as cm:
            generate_pi_pdf_bytes(None)

        self.assertIn("required", str(cm.exception).lower())

    def test_generate_pdf_bytes_empty_details(self):
        """Test PDF generation with empty details"""
        pi_data = PIData(
            master=self.master,
            details=[],
            customer=self.customer
        )

        with self.assertRaises(PDFGenerationError) as cm:
            generate_pi_pdf_bytes(pi_data)

        # Error message should mention invalid or detail
        error_msg = str(cm.exception).lower()
        self.assertTrue("invalid" in error_msg or "detail" in error_msg)

    def test_generate_pdf_bytes_invalid_data(self):
        """Test PDF generation with invalid data"""
        # Create invalid PI data (missing master)
        pi_data = PIData(
            master=None,
            details=self.details,
            customer=self.customer
        )

        with self.assertRaises(PDFGenerationError) as cm:
            generate_pi_pdf_bytes(pi_data)

        self.assertIn("invalid", str(cm.exception).lower())

    def test_generate_pdf_file_success(self):
        """Test successful PDF generation to file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_pi.pdf"

            result_path = generate_pi_pdf(self.pi_data, str(output_path))

            # Check that file was created
            self.assertTrue(Path(result_path).exists())

            # Check file size
            file_size = Path(result_path).stat().st_size
            self.assertGreater(file_size, 0)

            # Check PDF signature
            with open(result_path, 'rb') as f:
                header = f.read(4)
                self.assertEqual(header, b'%PDF')

    def test_generate_pdf_file_creates_directory(self):
        """Test that generate_pi_pdf creates output directory if it doesn't exist"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "subdir" / "nested" / "test_pi.pdf"

            result_path = generate_pi_pdf(self.pi_data, str(output_path))

            # Check that file and directories were created
            self.assertTrue(Path(result_path).exists())
            self.assertTrue(Path(result_path).parent.exists())

    def test_generate_pdf_with_single_item(self):
        """Test PDF generation with single line item"""
        pi_data = PIData(
            master=self.master,
            details=[self.details[0]],
            customer=self.customer
        )

        pdf_bytes = generate_pi_pdf_bytes(pi_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b'%PDF'))

    def test_generate_pdf_with_many_items(self):
        """Test PDF generation with many items (multiple pages)"""
        # Create 10 items to trigger pagination
        many_details = []
        for i in range(1, 11):
            detail = PIDetail(
                sc_no="T25C99",
                item_seq=i,
                product_code=f"PROD-{i:03d}",
                product_name_1=f"Test Product {i} Name Line 1",
                product_name_2=f"Test Product {i} Description Line 2",
                quantity=1000.0 * i,
                unit="PCS",
                unit_price=1.00 + (i * 0.1),
                amount=1000.0 * i * (1.00 + (i * 0.1))
            )
            many_details.append(detail)

        pi_data = PIData(
            master=self.master,
            details=many_details,
            customer=self.customer
        )

        pdf_bytes = generate_pi_pdf_bytes(pi_data)

        # Should generate successfully with multiple pages
        self.assertIsInstance(pdf_bytes, bytes)
        # Multi-page PDF should be larger than single page (reportlab compresses well)
        self.assertGreater(len(pdf_bytes), 3000)

    def test_pi_data_calculated_total(self):
        """Test that calculated total matches sum of details"""
        expected_total = sum(d.calculated_amount for d in self.details)
        self.assertAlmostEqual(self.pi_data.calculated_total, expected_total, places=2)

    def test_pi_data_validity(self):
        """Test PI data validity check"""
        self.assertTrue(self.pi_data.is_valid)

        # Invalid: no details
        invalid_pi = PIData(master=self.master, details=[], customer=self.customer)
        self.assertFalse(invalid_pi.is_valid)

        # Invalid: no master
        invalid_pi = PIData(master=None, details=self.details, customer=self.customer)
        self.assertFalse(invalid_pi.is_valid)


class TestPDFContentValidation(unittest.TestCase):
    """Test that PDF contains expected content (basic validation)"""

    def setUp(self):
        """Set up test data"""
        self.master = PIMaster(
            sc_no="T25C99",
            create_date="20251223",
            customer_code="TEST01",
            customer_po="PO-2025-TEST",
            trade_terms="FOB TAIWAN USD",
            payment_terms="T/T 30 DAYS",
            total_amount=12480.00
        )

        self.customer = PICustomer(
            code="TEST01",
            name="TEST CUSTOMER COMPANY LTD.",
            short_name="TEST CUSTOMER",
            address="123 TEST STREET, TEST CITY"
        )

        self.details = [
            PIDetail(
                sc_no="T25C99",
                item_seq=1,
                product_code="PROD-001",
                product_name_1="Test Product",
                product_name_2="",
                quantity=6000.0,
                unit="PCS",
                unit_price=2.08,
                amount=12480.00
            )
        ]

        self.pi_data = PIData(
            master=self.master,
            details=self.details,
            customer=self.customer
        )

    def test_pdf_basic_structure(self):
        """Test that PDF has basic structure"""
        pdf_bytes = generate_pi_pdf_bytes(self.pi_data)

        # Check PDF version
        self.assertTrue(pdf_bytes.startswith(b'%PDF-1.'))

        # Check EOF marker
        self.assertTrue(b'%%EOF' in pdf_bytes)

        # Check that PDF has reasonable size
        self.assertGreater(len(pdf_bytes), 2000)

        # Check for ReportLab signature in PDF
        pdf_str = pdf_bytes.decode('latin-1', errors='ignore')
        self.assertIn('ReportLab', pdf_str)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestPDFGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestPDFContentValidation))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("PDF Generator Module - Unit Tests")
    print("=" * 70 + "\n")

    success = run_tests()

    print("\n" + "=" * 70)
    if success:
        print("All tests PASSED!")
    else:
        print("Some tests FAILED!")
    print("=" * 70 + "\n")

    sys.exit(0 if success else 1)
