"""
Complete Workflow Example: From Database to Filed PDF

This script demonstrates the complete PI generation workflow:
1. Query PI data from database
2. Generate PDF
3. Save to proper location with correct naming

This is the full integration of Tasks 2, 3, and 4.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from pi_generator import (
    get_pi_data,
    list_recent_sc_numbers,
    generate_pi_pdf_bytes,
    save_pi_pdf,
    get_pi_filepath,
    PIDataQueryError,
    PDFGenerationError,
    FileManagerError
)


def generate_and_save_pi(sc_no: str, base_dir: str = "output") -> str:
    """
    Complete workflow: Query data, generate PDF, and save to file.

    Args:
        sc_no: S/C number to process
        base_dir: Base directory for saving (default: "output" for testing)

    Returns:
        Path where PDF was saved

    Raises:
        PIDataQueryError: If data query fails
        PDFGenerationError: If PDF generation fails
        FileManagerError: If file save fails
    """
    print(f"\n{'='*70}")
    print(f"Processing S/C: {sc_no}")
    print(f"{'='*70}\n")

    # Step 1: Query PI data from database
    print("Step 1: Querying PI data from database...")
    pi_data = get_pi_data(sc_no)
    print(f"  Customer: {pi_data.customer.code} - {pi_data.customer.name}")
    print(f"  S/C Number: {pi_data.master.sc_no}")
    print(f"  Customer PO: {pi_data.master.customer_po}")
    print(f"  Items: {pi_data.item_count}")
    print(f"  Total: ${pi_data.master.total_amount:,.2f}")

    # Step 2: Generate PDF
    print("\nStep 2: Generating PDF...")
    pdf_bytes = generate_pi_pdf_bytes(pi_data)
    print(f"  PDF generated: {len(pdf_bytes):,} bytes")

    # Step 3: Determine file path
    print("\nStep 3: Determining file path...")
    filepath = get_pi_filepath(pi_data, base_dir=base_dir)
    print(f"  Target path: {filepath}")

    # Step 4: Save PDF to file
    print("\nStep 4: Saving PDF to file...")
    saved_path = save_pi_pdf(pi_data, pdf_bytes, base_dir=base_dir)
    print(f"  Saved to: {saved_path}")

    # Verify file
    if os.path.exists(saved_path):
        file_size = os.path.getsize(saved_path)
        print(f"  File verified: {file_size:,} bytes")
    else:
        raise FileManagerError(f"File was not created: {saved_path}")

    print(f"\n{'='*70}")
    print("SUCCESS: PI PDF generated and saved!")
    print(f"{'='*70}\n")

    return saved_path


def main():
    """Main function"""
    print("\n" + "="*70)
    print("PI GENERATOR - COMPLETE WORKFLOW DEMONSTRATION")
    print("="*70)

    # Check command line arguments
    if len(sys.argv) > 1:
        sc_numbers = [sys.argv[1]]
        print(f"\nProcessing specified S/C: {sc_numbers[0]}")
    else:
        # Get recent S/C numbers
        print("\nGetting recent S/C numbers from database...")
        sc_numbers = list_recent_sc_numbers(3)
        if not sc_numbers:
            print("ERROR: No S/C numbers found in database")
            return 1
        print(f"Found {len(sc_numbers)} recent S/C numbers:")
        for i, sc in enumerate(sc_numbers, 1):
            print(f"  {i}. {sc}")

    # Process each S/C number
    results = []
    for sc_no in sc_numbers:
        try:
            saved_path = generate_and_save_pi(sc_no, base_dir="output")
            results.append((sc_no, saved_path, True, None))
        except (PIDataQueryError, PDFGenerationError, FileManagerError) as e:
            print(f"\nERROR processing {sc_no}: {e}")
            results.append((sc_no, None, False, str(e)))
        except Exception as e:
            print(f"\nUNEXPECTED ERROR processing {sc_no}: {e}")
            import traceback
            traceback.print_exc()
            results.append((sc_no, None, False, str(e)))

    # Summary
    print("\n" + "="*70)
    print("PROCESSING SUMMARY")
    print("="*70)

    successful = sum(1 for _, _, success, _ in results if success)
    total = len(results)

    for sc_no, saved_path, success, error in results:
        if success:
            print(f"  [+] {sc_no} -> {saved_path}")
        else:
            print(f"  [X] {sc_no} -> FAILED: {error[:50]}")

    print(f"\nTotal: {successful}/{total} successful")

    if successful == total:
        print("\nSUCCESS: All PI PDFs generated and saved!")
    else:
        print(f"\nWARNING: {total - successful} failed")

    print("="*70 + "\n")

    return 0 if successful == total else 1


if __name__ == "__main__":
    sys.exit(main())
