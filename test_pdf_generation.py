"""
Test script for PDF generation

This script demonstrates generating a PI PDF from real database data.

Usage:
    python test_pdf_generation.py [SC_NO]

If SC_NO is not provided, uses the most recent S/C from the database.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pi_generator.pi_data import get_pi_data, list_recent_sc_numbers
from pi_generator.pdf_generator import generate_pi_pdf, generate_pi_pdf_bytes


def main():
    print("\n" + "=" * 70)
    print("PDF Generation Test")
    print("=" * 70 + "\n")

    # Get S/C number
    if len(sys.argv) > 1:
        sc_no = sys.argv[1].strip().upper()
        print(f"Using S/C from command line: {sc_no}")
    else:
        print("No S/C number provided, fetching recent S/C numbers...")
        recent = list_recent_sc_numbers(5)
        if not recent:
            print("ERROR: No S/C numbers found in database")
            return 1

        print(f"\nRecent S/C numbers:")
        for i, sc in enumerate(recent, 1):
            print(f"  {i}. {sc}")

        sc_no = recent[0]
        print(f"\nUsing: {sc_no}")

    # Get PI data
    print(f"\n" + "-" * 70)
    print("Loading PI data...")
    print("-" * 70)

    try:
        pi_data = get_pi_data(sc_no)
    except Exception as e:
        print(f"ERROR loading PI data: {e}")
        return 1

    # Display PI data summary
    print(f"\nPI Data loaded successfully:")
    print(f"  S/C Number:    {pi_data.master.sc_no}")
    print(f"  Customer:      {pi_data.customer.name}")
    print(f"  Customer PO:   {pi_data.master.customer_po}")
    print(f"  Date:          {pi_data.master.formatted_date}")
    print(f"  Trade Terms:   {pi_data.master.trade_terms}")
    print(f"  Payment Terms: {pi_data.master.payment_terms}")
    print(f"  Items:         {pi_data.item_count}")
    print(f"  Total Amount:  ${pi_data.calculated_total:,.2f}")

    # Generate PDF
    print(f"\n" + "-" * 70)
    print("Generating PDF...")
    print("-" * 70)

    output_path = f"output/PI_{sc_no}.pdf"

    try:
        result_path = generate_pi_pdf(pi_data, output_path)
    except Exception as e:
        print(f"ERROR generating PDF: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Check file
    pdf_file = Path(result_path)
    if not pdf_file.exists():
        print(f"ERROR: PDF file was not created at {result_path}")
        return 1

    file_size = pdf_file.stat().st_size

    print(f"\nPDF generated successfully!")
    print(f"  Path: {result_path}")
    print(f"  Size: {file_size:,} bytes")

    # Test bytes generation too
    print(f"\n" + "-" * 70)
    print("Testing bytes generation...")
    print("-" * 70)

    try:
        pdf_bytes = generate_pi_pdf_bytes(pi_data)
        print(f"Generated {len(pdf_bytes):,} bytes in memory")
    except Exception as e:
        print(f"ERROR generating PDF bytes: {e}")
        return 1

    print("\n" + "=" * 70)
    print("SUCCESS - All tests passed!")
    print("=" * 70 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
