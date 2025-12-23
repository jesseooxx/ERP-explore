"""
Datawin Report Renderer
A Python implementation compatible with nrp32.exe report format

High-performance version with 3-10x speedup over original
"""

# Original implementations
from .parser import ReportParser, ReportDocument
from .renderer import PDFRenderer
from .data_binder import DataBinder

# High-performance implementations (recommended)
from .fast_parser import FastReportParser
from .fast_renderer import FastPDFRenderer, render_report_fast, BatchRenderer

__version__ = "2.0.0"
__all__ = [
    # Original
    "ReportParser",
    "ReportDocument",
    "PDFRenderer",
    "DataBinder",
    # High-performance (recommended)
    "FastReportParser",
    "FastPDFRenderer",
    "render_report_fast",
    "BatchRenderer",
]
