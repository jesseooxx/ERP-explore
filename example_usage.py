"""
Example Usage: PI PDF Generation

This script demonstrates how to use the pi_generator package to:
1. Query PI data from the database
2. Generate PDF files
3. Generate PDF bytes (for email attachments, etc.)

Usage:
    python example_usage.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pi_generator import (
    get_pi_data,
    generate_pi_pdf,
    generate_pi_pdf_bytes,
    list_recent_sc_numbers,
    PIDataQueryError,
    PDFGenerationError
)


def example_1_basic_usage():
    """Example 1: Basic PDF generation"""
    print("\n" + "=" * 70)
    print("Example 1: Basic PDF Generation")
    print("=" * 70)

    try:
        # Get PI data
        sc_no = "T17104"
        print(f"\n1. Loading PI data for S/C {sc_no}...")
        pi_data = get_pi_data(sc_no)

        print(f"   Customer: {pi_data.customer.name}")
        print(f"   Items: {pi_data.item_count}")
        print(f"   Total: ${pi_data.calculated_total:,.2f}")

        # Generate PDF
        print(f"\n2. Generating PDF...")
        output_path = f"output/examples/PI_{sc_no}.pdf"
        pdf_path = generate_pi_pdf(pi_data, output_path)

        print(f"   SUCCESS! PDF saved to:")
        print(f"   {pdf_path}")

    except (PIDataQueryError, PDFGenerationError) as e:
        print(f"   ERROR: {e}")


def example_2_bytes_generation():
    """Example 2: Generate PDF as bytes (for email attachments)"""
    print("\n" + "=" * 70)
    print("Example 2: Generate PDF as Bytes")
    print("=" * 70)

    try:
        # Get PI data
        sc_no = "T17103"
        print(f"\n1. Loading PI data for S/C {sc_no}...")
        pi_data = get_pi_data(sc_no)

        # Generate PDF bytes
        print(f"\n2. Generating PDF bytes (in memory)...")
        pdf_bytes = generate_pi_pdf_bytes(pi_data)

        print(f"   SUCCESS! Generated {len(pdf_bytes):,} bytes")
        print(f"   This can be used for:")
        print(f"   - Email attachments")
        print(f"   - Web API responses")
        print(f"   - Cloud storage upload")

        # Optionally save it
        output_path = Path(f"output/examples/PI_{sc_no}_from_bytes.pdf")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        print(f"\n   Also saved to: {output_path.absolute()}")

    except (PIDataQueryError, PDFGenerationError) as e:
        print(f"   ERROR: {e}")


def example_3_batch_generation():
    """Example 3: Batch generate PDFs for recent S/C numbers"""
    print("\n" + "=" * 70)
    print("Example 3: Batch PDF Generation")
    print("=" * 70)

    try:
        # Get recent S/C numbers
        print(f"\n1. Fetching recent S/C numbers...")
        sc_numbers = list_recent_sc_numbers(3)
        print(f"   Found {len(sc_numbers)} S/C numbers: {', '.join(sc_numbers)}")

        # Generate PDFs for each
        print(f"\n2. Generating PDFs...")
        for i, sc_no in enumerate(sc_numbers, 1):
            try:
                print(f"\n   [{i}/{len(sc_numbers)}] Processing {sc_no}...")

                # Get data
                pi_data = get_pi_data(sc_no)
                print(f"       Customer: {pi_data.customer.name}")
                print(f"       Items: {pi_data.item_count}")

                # Generate PDF
                output_path = f"output/examples/batch/PI_{sc_no}.pdf"
                pdf_path = generate_pi_pdf(pi_data, output_path)

                # Get file size
                file_size = Path(pdf_path).stat().st_size
                print(f"       Generated: {file_size:,} bytes")

            except (PIDataQueryError, PDFGenerationError) as e:
                print(f"       ERROR: {e}")
                continue

        print(f"\n   Batch generation complete!")

    except Exception as e:
        print(f"   ERROR: {e}")


def example_4_error_handling():
    """Example 4: Error handling"""
    print("\n" + "=" * 70)
    print("Example 4: Error Handling")
    print("=" * 70)

    # Test with invalid S/C number
    print(f"\n1. Testing with invalid S/C number...")
    try:
        pi_data = get_pi_data("INVALID123")
        print(f"   Unexpected success!")
    except PIDataQueryError as e:
        print(f"   Caught PIDataQueryError: {e}")

    # Test with empty data
    print(f"\n2. Testing with None PIData...")
    try:
        pdf_bytes = generate_pi_pdf_bytes(None)
        print(f"   Unexpected success!")
    except PDFGenerationError as e:
        print(f"   Caught PDFGenerationError: {e}")


def main():
    """Run all examples"""
    print("\n" + "=" * 70)
    print("PI PDF Generator - Usage Examples")
    print("=" * 70)

    # Run examples
    example_1_basic_usage()
    example_2_bytes_generation()
    example_3_batch_generation()
    example_4_error_handling()

    print("\n" + "=" * 70)
    print("All examples completed!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
