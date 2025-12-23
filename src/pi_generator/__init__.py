"""
PI Report Generator Package

This package provides functionality to generate PI (Proforma Invoice) reports
directly from SQL Server database, bypassing ERP/NRP rendering.

Main Components:
- db: Database connection management
- pi_data: PI data query and structures
- pdf_generator: PDF generation from PI data
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
    # Exceptions
    'PIDataQueryError',
    'PDFGenerationError',
]
