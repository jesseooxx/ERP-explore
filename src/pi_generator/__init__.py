"""
PI Report Generator Package

This package provides functionality to generate PI (Proforma Invoice) reports
directly from SQL Server database, bypassing ERP/NRP rendering.

Main Components:
- db: Database connection management
- pi_data: PI data query and structures
- pdf_generator: PDF generation from PI data
- file_manager: Automatic file naming and filing
"""

__version__ = "0.1.0"

# Import main classes and functions for convenient access
from .db import DatabaseConnection
from .pi_data import (
    PIData,
    PIMaster,
    PIDetail,
    PICustomer,
    get_pi_data,
    list_recent_sc_numbers,
    PIDataQueryError
)
from .pdf_generator import (
    generate_pi_pdf,
    generate_pi_pdf_bytes,
    PDFGenerationError
)
from .file_manager import (
    get_pi_filename,
    get_pi_filepath,
    save_pi_pdf,
    ensure_directory_exists,
    get_customer_directory,
    list_pi_files,
    sanitize_filename,
    validate_pi_data_for_filing,
    FileManagerError
)

__all__ = [
    # Database
    'DatabaseConnection',
    # Data structures
    'PIData',
    'PIMaster',
    'PIDetail',
    'PICustomer',
    # Data query functions
    'get_pi_data',
    'list_recent_sc_numbers',
    # PDF generation functions
    'generate_pi_pdf',
    'generate_pi_pdf_bytes',
    # File management functions
    'get_pi_filename',
    'get_pi_filepath',
    'save_pi_pdf',
    'ensure_directory_exists',
    'get_customer_directory',
    'list_pi_files',
    'sanitize_filename',
    'validate_pi_data_for_filing',
    # Exceptions
    'PIDataQueryError',
    'PDFGenerationError',
    'FileManagerError',
]
