r"""
PI File Management Module

This module handles automatic naming and filing of PI PDF files according to
the standard naming convention.

Naming Rule:
    Pattern: Z:\LEILA\PI\{Cust#}\PI_ {Ref} ({ORDER}).pdf

    Where:
    - {Cust#} = Customer code (e.g., "604")
    - {Ref} = S/C number (e.g., "T25C22")
    - {ORDER} = Customer PO number (e.g., "506046")

    Example: Z:\LEILA\PI\604\PI_ T25C22 (506046).pdf

Usage:
    from pi_generator.file_manager import save_pi_pdf, get_pi_filepath

    # Get full file path
    filepath = get_pi_filepath(pi_data)

    # Save PDF to file
    saved_path = save_pi_pdf(pi_data, pdf_bytes)
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional

from .pi_data import PIData

# Configure logging
logger = logging.getLogger(__name__)

# Invalid filename characters that need to be sanitized
INVALID_FILENAME_CHARS = r'[<>:"/\\|?*]'


class FileManagerError(Exception):
    """Exception raised when file management operations fail"""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Remove or replace invalid characters from filename.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for Windows filesystem

    Example:
        >>> sanitize_filename('PI_ T25C22 (506046).pdf')
        'PI_ T25C22 (506046).pdf'
        >>> sanitize_filename('PI_ T/25C22 (506*046).pdf')
        'PI_ T_25C22 (506_046).pdf'
    """
    # Replace invalid characters with underscore
    sanitized = re.sub(INVALID_FILENAME_CHARS, '_', filename)
    # Remove leading/trailing spaces
    sanitized = sanitized.strip()
    return sanitized


def validate_pi_data_for_filing(pi_data: PIData) -> None:
    """
    Validate that PIData has all required fields for file naming.

    Args:
        pi_data: PIData object to validate

    Raises:
        FileManagerError: If required fields are missing or empty
    """
    errors = []

    # Check customer code
    if not pi_data.customer or not pi_data.customer.code:
        errors.append("Customer code is missing")
    elif not pi_data.customer.code.strip():
        errors.append("Customer code is empty")

    # Check S/C number
    if not pi_data.master or not pi_data.master.sc_no:
        errors.append("S/C number is missing")
    elif not pi_data.master.sc_no.strip():
        errors.append("S/C number is empty")

    # Check customer PO
    if not pi_data.master or not pi_data.master.customer_po:
        errors.append("Customer PO is missing")
    elif not pi_data.master.customer_po.strip():
        errors.append("Customer PO is empty")

    if errors:
        raise FileManagerError(
            f"PIData validation failed for file naming: {'; '.join(errors)}"
        )


def get_pi_filename(pi_data: PIData) -> str:
    """
    Generate PI filename according to naming convention.

    Pattern: PI_ {Ref} ({ORDER}).pdf

    Args:
        pi_data: PIData object containing master and customer information

    Returns:
        Filename string (e.g., "PI_ T25C22 (506046).pdf")

    Raises:
        FileManagerError: If required fields are missing

    Example:
        >>> filename = get_pi_filename(pi_data)
        >>> print(filename)
        PI_ T25C22 (506046).pdf
    """
    # Validate required fields
    validate_pi_data_for_filing(pi_data)

    # Extract components
    ref = pi_data.master.sc_no.strip()
    order = pi_data.master.customer_po.strip()

    # Build filename according to pattern
    # Note: There's a space after "PI_" in the pattern
    filename = f"PI_ {ref} ({order}).pdf"

    # Sanitize to ensure valid filename
    filename = sanitize_filename(filename)

    logger.debug(f"Generated filename: {filename}")
    return filename


def get_pi_filepath(pi_data: PIData, base_dir: str = r"Z:\LEILA\PI") -> str:
    r"""
    Generate full file path for PI PDF according to directory structure.

    Pattern: {base_dir}\{Cust#}\PI_ {Ref} ({ORDER}).pdf

    Args:
        pi_data: PIData object containing master and customer information
        base_dir: Base directory for PI files (default: Z:\LEILA\PI)

    Returns:
        Full file path string

    Raises:
        FileManagerError: If required fields are missing

    Example:
        >>> filepath = get_pi_filepath(pi_data)
        >>> print(filepath)
        Z:\LEILA\PI\604\PI_ T25C22 (506046).pdf

        >>> # For testing with local directory
        >>> filepath = get_pi_filepath(pi_data, base_dir="output")
        >>> print(filepath)
        output\604\PI_ T25C22 (506046).pdf
    """
    # Validate required fields
    validate_pi_data_for_filing(pi_data)

    # Extract customer code
    customer_code = pi_data.customer.code.strip()

    # Get filename
    filename = get_pi_filename(pi_data)

    # Build full path
    # Use Path for proper path handling across platforms
    full_path = Path(base_dir) / customer_code / filename

    logger.debug(f"Generated filepath: {full_path}")
    return str(full_path)


def ensure_directory_exists(directory: str) -> None:
    """
    Create directory if it doesn't exist.

    Args:
        directory: Directory path to create

    Raises:
        FileManagerError: If directory creation fails
    """
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")
    except Exception as e:
        raise FileManagerError(f"Failed to create directory {directory}: {e}")


def save_pi_pdf(
    pi_data: PIData,
    pdf_bytes: bytes,
    base_dir: str = r"Z:\LEILA\PI"
) -> str:
    r"""
    Save PI PDF to the correct location with proper naming.

    This function:
    1. Generates the proper filename and path
    2. Creates customer subdirectory if needed
    3. Saves the PDF file
    4. Returns the full path where file was saved

    Args:
        pi_data: PIData object containing master and customer information
        pdf_bytes: PDF file content as bytes
        base_dir: Base directory for PI files (default: Z:\LEILA\PI)

    Returns:
        Full file path where PDF was saved

    Raises:
        FileManagerError: If validation or save operation fails

    Example:
        >>> # Generate PDF bytes (from pdf_generator module)
        >>> pdf_bytes = generate_pi_pdf_bytes(pi_data)
        >>>
        >>> # Save to production location
        >>> saved_path = save_pi_pdf(pi_data, pdf_bytes)
        >>> print(f"Saved to: {saved_path}")
        Saved to: Z:\LEILA\PI\604\PI_ T25C22 (506046).pdf
        >>>
        >>> # Save to test location
        >>> saved_path = save_pi_pdf(pi_data, pdf_bytes, base_dir="output")
        >>> print(f"Saved to: {saved_path}")
        Saved to: output\604\PI_ T25C22 (506046).pdf
    """
    # Validate pdf_bytes
    if not pdf_bytes:
        raise FileManagerError("PDF bytes are empty")

    if not isinstance(pdf_bytes, bytes):
        raise FileManagerError(
            f"pdf_bytes must be bytes, got {type(pdf_bytes).__name__}"
        )

    # Get full file path
    full_path = get_pi_filepath(pi_data, base_dir)

    # Get directory path
    directory = os.path.dirname(full_path)

    # Create directory if needed
    ensure_directory_exists(directory)

    # Save PDF file
    try:
        with open(full_path, 'wb') as f:
            f.write(pdf_bytes)

        file_size = len(pdf_bytes)
        logger.info(
            f"Saved PI PDF: {full_path} ({file_size:,} bytes)"
        )

        return full_path

    except Exception as e:
        raise FileManagerError(f"Failed to save PDF to {full_path}: {e}")


def get_customer_directory(customer_code: str, base_dir: str = r"Z:\LEILA\PI") -> str:
    r"""
    Get the directory path for a specific customer.

    Args:
        customer_code: Customer code (e.g., "604")
        base_dir: Base directory for PI files

    Returns:
        Full directory path for customer

    Example:
        >>> get_customer_directory("604")
        'Z:\\LEILA\\PI\\604'
    """
    return str(Path(base_dir) / customer_code.strip())


def list_pi_files(customer_code: str, base_dir: str = r"Z:\LEILA\PI") -> list:
    """
    List all PI files for a specific customer.

    Args:
        customer_code: Customer code (e.g., "604")
        base_dir: Base directory for PI files

    Returns:
        List of PI file paths for the customer

    Example:
        >>> files = list_pi_files("604")
        >>> for f in files:
        ...     print(f)
    """
    customer_dir = get_customer_directory(customer_code, base_dir)

    if not os.path.exists(customer_dir):
        logger.debug(f"Customer directory does not exist: {customer_dir}")
        return []

    try:
        # List all PDF files that match PI naming pattern
        files = []
        for filename in os.listdir(customer_dir):
            if filename.startswith("PI_") and filename.endswith(".pdf"):
                full_path = os.path.join(customer_dir, filename)
                files.append(full_path)

        logger.debug(f"Found {len(files)} PI files for customer {customer_code}")
        return sorted(files)

    except Exception as e:
        logger.error(f"Error listing files in {customer_dir}: {e}")
        return []


if __name__ == "__main__":
    # Test the module
    import sys
    from .pi_data import get_pi_data

    print("\n" + "=" * 60)
    print("PI File Management Module - Test")
    print("=" * 60 + "\n")

    # Test with a sample S/C number
    if len(sys.argv) > 1:
        test_sc_no = sys.argv[1]
    else:
        test_sc_no = "T25C22"  # Default test S/C

    try:
        # Get PI data
        print(f"Loading PI data for {test_sc_no}...")
        pi_data = get_pi_data(test_sc_no)
        print(f"Customer: {pi_data.customer.code} - {pi_data.customer.name}")
        print(f"S/C: {pi_data.master.sc_no}")
        print(f"PO: {pi_data.master.customer_po}")

        # Test filename generation
        print("\n" + "-" * 60)
        print("FILENAME GENERATION")
        print("-" * 60)
        filename = get_pi_filename(pi_data)
        print(f"Filename: {filename}")

        # Test filepath generation
        print("\n" + "-" * 60)
        print("FILEPATH GENERATION")
        print("-" * 60)

        # Production path
        prod_path = get_pi_filepath(pi_data)
        print(f"Production: {prod_path}")

        # Test path
        test_path = get_pi_filepath(pi_data, base_dir="output")
        print(f"Test:       {test_path}")

        # Test directory creation
        print("\n" + "-" * 60)
        print("DIRECTORY CREATION TEST")
        print("-" * 60)
        test_dir = os.path.dirname(test_path)
        print(f"Creating: {test_dir}")
        ensure_directory_exists(test_dir)
        print(f"Success: Directory exists")

        # Test file saving (with dummy PDF)
        print("\n" + "-" * 60)
        print("FILE SAVE TEST (with dummy content)")
        print("-" * 60)
        dummy_pdf = b"%PDF-1.4\nDummy PDF for testing\n%%EOF"
        saved_path = save_pi_pdf(pi_data, dummy_pdf, base_dir="output")
        print(f"Saved to: {saved_path}")
        print(f"File exists: {os.path.exists(saved_path)}")
        print(f"File size: {os.path.getsize(saved_path)} bytes")

        # Test listing files
        print("\n" + "-" * 60)
        print("LIST FILES TEST")
        print("-" * 60)
        files = list_pi_files(pi_data.customer.code, base_dir="output")
        print(f"Found {len(files)} file(s) for customer {pi_data.customer.code}:")
        for f in files:
            print(f"  - {f}")

        print("\n" + "=" * 60)
        print("SUCCESS - All tests passed")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\nERROR: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
