r"""
PI Generator - Main Entry Point

One-click solution to generate PI PDFs from database:
1. Query PI data from database
2. Generate PDF
3. Save to Z:\LEILA\PI\{Cust#}\PI_ {Ref} ({ORDER}).pdf
4. Open in PDF-XChange Editor

Usage:
    python generate_pi.py T25C22
    python generate_pi.py T25C22 T25C23 T25C24
    python generate_pi.py --test T25C22
    python generate_pi.py --list
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import Optional, List, Tuple

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


# Common PDF-XChange Editor installation paths
PDF_XCHANGE_PATHS = [
    r"C:\Program Files\Tracker Software\PDF Editor\PDFXEdit.exe",
    r"C:\Program Files (x86)\Tracker Software\PDF Editor\PDFXEdit.exe",
    r"C:\Program Files\Tracker Software\PDF-XChange Editor\PDFXEdit.exe",
    r"C:\Program Files (x86)\Tracker Software\PDF-XChange Editor\PDFXEdit.exe",
]


def find_pdf_viewer() -> Optional[str]:
    """
    Find PDF-XChange Editor executable.

    Returns:
        Path to PDF-XChange Editor if found, None otherwise
    """
    for path in PDF_XCHANGE_PATHS:
        if os.path.exists(path):
            return path
    return None


def open_pdf_file(filepath: str) -> bool:
    """
    Open PDF file in PDF-XChange Editor or default viewer.

    Args:
        filepath: Path to PDF file

    Returns:
        True if successfully opened, False otherwise
    """
    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        return False

    # Try PDF-XChange Editor first
    pdf_viewer = find_pdf_viewer()
    if pdf_viewer:
        try:
            print(f"Opening with PDF-XChange Editor...")
            subprocess.Popen([pdf_viewer, filepath])
            print(f"Opened: {filepath}")
            return True
        except Exception as e:
            print(f"Failed to open with PDF-XChange Editor: {e}")
            print("Falling back to default PDF viewer...")

    # Fall back to default system PDF viewer
    try:
        print(f"Opening with default PDF viewer...")
        os.startfile(filepath)
        print(f"Opened: {filepath}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to open PDF: {e}")
        return False


def generate_and_open_pi(
    sc_no: str,
    base_dir: str = r"Z:\LEILA\PI",
    open_pdf: bool = True
) -> str:
    r"""
    Complete workflow: Query data, generate PDF, save, and optionally open.

    Args:
        sc_no: S/C number to process
        base_dir: Base directory for saving (default: Z:\LEILA\PI)
        open_pdf: Whether to open the PDF after generation (default: True)

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
    print("[1/4] Querying PI data from database...")
    pi_data = get_pi_data(sc_no)
    print(f"  Customer: {pi_data.customer.code} - {pi_data.customer.name}")
    print(f"  S/C Number: {pi_data.master.sc_no}")
    print(f"  Customer PO: {pi_data.master.customer_po}")
    print(f"  Items: {pi_data.item_count}")
    print(f"  Total: ${pi_data.master.total_amount:,.2f}")

    # Step 2: Generate PDF
    print("\n[2/4] Generating PDF...")
    pdf_bytes = generate_pi_pdf_bytes(pi_data)
    print(f"  PDF generated: {len(pdf_bytes):,} bytes")

    # Step 3: Determine file path
    print("\n[3/4] Determining file path...")
    filepath = get_pi_filepath(pi_data, base_dir=base_dir)
    print(f"  Target path: {filepath}")

    # Step 4: Save PDF to file
    print("\n[4/4] Saving PDF to file...")
    saved_path = save_pi_pdf(pi_data, pdf_bytes, base_dir=base_dir)

    # Verify file
    if os.path.exists(saved_path):
        file_size = os.path.getsize(saved_path)
        print(f"  Saved: {saved_path}")
        print(f"  Size: {file_size:,} bytes")
    else:
        raise FileManagerError(f"File was not created: {saved_path}")

    # Open PDF if requested
    if open_pdf:
        print(f"\n[5/4] Opening PDF...")
        open_pdf_file(saved_path)

    print(f"\n{'='*70}")
    print("SUCCESS: PI PDF generated, saved, and opened!")
    print(f"{'='*70}\n")

    return saved_path


def list_recent_sc(limit: int = 20) -> None:
    """
    List recent S/C numbers from database.

    Args:
        limit: Number of S/C numbers to list
    """
    print(f"\nQuerying recent S/C numbers (limit: {limit})...\n")

    try:
        sc_numbers = list_recent_sc_numbers(limit)

        if not sc_numbers:
            print("No S/C numbers found in database.")
            return

        print(f"Found {len(sc_numbers)} recent S/C numbers:\n")
        for i, sc in enumerate(sc_numbers, 1):
            print(f"  {i:2d}. {sc}")

        print(f"\nUsage: python generate_pi.py {sc_numbers[0]}")

    except Exception as e:
        print(f"ERROR: Failed to list S/C numbers: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Generate PI PDFs from database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate single PI and open it:
    python generate_pi.py T25C22

  Generate multiple PIs:
    python generate_pi.py T25C22 T25C23 T25C24

  Generate without opening (batch mode):
    python generate_pi.py --no-open T25C22 T25C23

  Use test output directory:
    python generate_pi.py --test T25C22

  List recent S/C numbers:
    python generate_pi.py --list
        """
    )

    parser.add_argument(
        'sc_numbers',
        nargs='*',
        help='S/C numbers to process (e.g., T25C22)'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Use test output directory (./output) instead of production (Z:\\LEILA\\PI)'
    )

    parser.add_argument(
        '--no-open',
        action='store_true',
        help='Do not open PDFs after generation (useful for batch processing)'
    )

    parser.add_argument(
        '--list',
        action='store_true',
        help='List recent S/C numbers from database'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=20,
        help='Number of S/C numbers to list (default: 20)'
    )

    args = parser.parse_args()

    # Handle --list option
    if args.list:
        list_recent_sc(args.limit)
        return 0

    # Check if S/C numbers were provided
    if not args.sc_numbers:
        parser.print_help()
        print("\nERROR: No S/C numbers specified. Use --list to see available S/C numbers.")
        return 1

    # Determine base directory
    base_dir = "output" if args.test else r"Z:\LEILA\PI"

    # Determine whether to open PDFs
    open_pdf = not args.no_open

    # Print header
    print("\n" + "="*70)
    print("PI GENERATOR - One-Click PDF Generation")
    print("="*70)
    print(f"Base directory: {base_dir}")
    print(f"Open PDFs: {'Yes' if open_pdf else 'No'}")
    print(f"Processing {len(args.sc_numbers)} S/C number(s)")
    print("="*70)

    # Process each S/C number
    results: List[Tuple[str, Optional[str], bool, Optional[str]]] = []

    for sc_no in args.sc_numbers:
        try:
            saved_path = generate_and_open_pi(sc_no, base_dir=base_dir, open_pdf=open_pdf)
            results.append((sc_no, saved_path, True, None))

        except PIDataQueryError as e:
            print(f"\nERROR processing {sc_no}: {e}")
            results.append((sc_no, None, False, f"Data query error: {e}"))

        except PDFGenerationError as e:
            print(f"\nERROR processing {sc_no}: {e}")
            results.append((sc_no, None, False, f"PDF generation error: {e}"))

        except FileManagerError as e:
            print(f"\nERROR processing {sc_no}: {e}")
            results.append((sc_no, None, False, f"File management error: {e}"))

        except Exception as e:
            print(f"\nUNEXPECTED ERROR processing {sc_no}: {e}")
            import traceback
            traceback.print_exc()
            results.append((sc_no, None, False, f"Unexpected error: {e}"))

    # Print summary
    print("\n" + "="*70)
    print("PROCESSING SUMMARY")
    print("="*70)

    successful = sum(1 for _, _, success, _ in results if success)
    total = len(results)

    for sc_no, saved_path, success, error in results:
        if success:
            print(f"  [+] {sc_no} -> {saved_path}")
        else:
            error_msg = error[:50] if error else "Unknown error"
            print(f"  [X] {sc_no} -> FAILED: {error_msg}")

    print(f"\nTotal: {successful}/{total} successful")

    if successful == total:
        print("\nSUCCESS: All PI PDFs generated and saved!")
    else:
        print(f"\nWARNING: {total - successful} failed")

    print("="*70 + "\n")

    return 0 if successful == total else 1


if __name__ == "__main__":
    sys.exit(main())
