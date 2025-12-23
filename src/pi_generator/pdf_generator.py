"""
PDF Generation Module for Proforma Invoice

This module generates professional PDF reports for Proforma Invoices using reportlab.
It takes PIData objects and produces formatted PDFs matching the company's standard format.

Usage:
    from pi_generator.pdf_generator import generate_pi_pdf, generate_pi_pdf_bytes
    from pi_generator.pi_data import get_pi_data

    # Get PI data
    pi_data = get_pi_data("T25C22")

    # Generate PDF file
    output_path = generate_pi_pdf(pi_data, "output/PI_T25C22.pdf")

    # Or get PDF as bytes
    pdf_bytes = generate_pi_pdf_bytes(pi_data)
"""

import logging
from typing import Optional
from io import BytesIO
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from num2words import num2words

from .pi_data import PIData, PIDetail

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# Exception Classes
# ============================================================================

class PDFGenerationError(Exception):
    """Exception raised when PDF generation fails"""
    pass


# ============================================================================
# Configuration Constants
# ============================================================================

class PDFConfig:
    """PDF layout configuration"""

    # Page settings
    PAGE_SIZE = A4
    PAGE_WIDTH, PAGE_HEIGHT = A4

    # Margins (0.75 inch = 1.905 cm on sides, 0.5 inch = 1.27 cm top/bottom)
    MARGIN_LEFT = 2.0 * cm
    MARGIN_RIGHT = 2.0 * cm
    MARGIN_TOP = 1.3 * cm
    MARGIN_BOTTOM = 1.3 * cm

    # Working area
    CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
    CONTENT_HEIGHT = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM

    # Logo placeholder (top-left)
    LOGO_PATH = None  # To be set later when actual logo is available
    LOGO_WIDTH = 100
    LOGO_HEIGHT = 50
    LOGO_X = MARGIN_LEFT
    LOGO_Y = PAGE_HEIGHT - MARGIN_TOP - LOGO_HEIGHT

    # Company info (top-right)
    COMPANY_INFO_X = PAGE_WIDTH - MARGIN_RIGHT
    COMPANY_INFO_Y = PAGE_HEIGHT - MARGIN_TOP - 10
    COMPANY_LINES = [
        "NO.1352, YONGCHUN E. RD., NANTUN DIST.",
        "TAICHUNG CITY 40842, TAIWAN(R.O.C)",
        "TEL:886-4-2382-0333 FAX:886-4-2382-3855 E:ftc@f-t-corp.com"
    ]

    # Title settings
    TITLE = "PROFORMA INVOICE"
    TITLE_FONT = "Helvetica-Bold"
    TITLE_SIZE = 18
    TITLE_Y = PAGE_HEIGHT - MARGIN_TOP - 80

    # Fonts
    FONT_NORMAL = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"
    FONT_SIZE_NORMAL = 9
    FONT_SIZE_SMALL = 8
    FONT_SIZE_HEADER = 10

    # Line items table
    TABLE_START_Y_FIRST_PAGE = 400  # Adjusted for customer info section
    TABLE_START_Y_CONTINUATION = 700  # More space on continuation pages
    LINE_HEIGHT = 14

    # Signature section height
    SIGNATURE_HEIGHT = 100


# ============================================================================
# Utility Functions
# ============================================================================

def extract_currency_symbol(trade_terms: str) -> str:
    """
    Extract currency symbol from trade_terms string.

    Args:
        trade_terms: Trade terms string (e.g., "FOB SHANGHAI USD")

    Returns:
        Currency symbol (e.g., "US$", "EUR", etc.)
    """
    if not trade_terms:
        return "US$"

    trade_terms_upper = trade_terms.upper()

    # Check for common currencies
    if "USD" in trade_terms_upper or "US$" in trade_terms_upper:
        return "US$"
    elif "EUR" in trade_terms_upper:
        return "EUR"
    elif "GBP" in trade_terms_upper or "£" in trade_terms:
        return "GBP"
    elif "JPY" in trade_terms_upper or "¥" in trade_terms:
        return "JPY"
    elif "CNY" in trade_terms_upper or "RMB" in trade_terms_upper:
        return "CNY"

    # Default to US$
    return "US$"


def amount_to_words(amount: float, currency: str = "US$") -> str:
    """
    Convert numeric amount to words.

    Args:
        amount: Numeric amount (e.g., 12480.00)
        currency: Currency symbol

    Returns:
        Amount in words (e.g., "TWELVE THOUSAND FOUR HUNDRED AND EIGHTY DOLLARS AND 00/100 ONLY")
    """
    try:
        # Split into dollars and cents
        dollars = int(amount)
        cents = int(round((amount - dollars) * 100))

        # Convert dollars to words
        if dollars == 0:
            dollar_words = "ZERO"
        else:
            dollar_words = num2words(dollars, lang='en').upper()

        # Format cents as fraction
        cents_str = f"{cents:02d}/100"

        # Determine currency name
        currency_name = "DOLLARS"
        if currency == "EUR":
            currency_name = "EUROS"
        elif currency == "GBP":
            currency_name = "POUNDS"
        elif currency == "JPY" or currency == "CNY":
            currency_name = "YUAN"

        # Combine
        result = f"{dollar_words} {currency_name} AND {cents_str} ONLY"

        return result

    except Exception as e:
        logger.warning(f"Error converting amount to words: {e}")
        return f"{currency} {amount:,.2f}"


def format_date_invoice(date_str: str) -> str:
    """
    Format date for invoice (e.g., "2025-12-23" -> "DEC. 23, 2025")

    Args:
        date_str: Date string in YYYY-MM-DD format

    Returns:
        Formatted date string
    """
    try:
        # Parse date
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")

        # Format as "DEC. 23, 2025"
        month_abbr = date_obj.strftime("%b").upper()
        day = date_obj.day
        year = date_obj.year

        return f"{month_abbr}. {day}, {year}"

    except Exception as e:
        logger.warning(f"Error formatting date: {e}")
        return date_str


def format_quantity(qty: float, unit: str) -> str:
    """
    Format quantity with unit (e.g., 6000.0, "PCS" -> "6,000 PCS")

    Args:
        qty: Quantity value
        unit: Unit string

    Returns:
        Formatted quantity string
    """
    # Format quantity with thousand separator, no decimal if whole number
    if qty == int(qty):
        qty_str = f"{int(qty):,}"
    else:
        qty_str = f"{qty:,.2f}"

    return f"{qty_str} {unit}"


def format_currency(amount: float, currency: str = "US$") -> str:
    """
    Format currency amount (e.g., 12480.00 -> "US$ 12,480.00")

    Args:
        amount: Amount value
        currency: Currency symbol

    Returns:
        Formatted currency string
    """
    return f"{currency} {amount:,.2f}"


# ============================================================================
# PDF Drawing Functions
# ============================================================================

def draw_page_header(c: canvas.Canvas, page_num: int) -> float:
    """
    Draw page header with logo, company info, and title.

    Args:
        c: ReportLab canvas
        page_num: Current page number

    Returns:
        Y position after header (for next content)
    """
    # Draw logo placeholder (rectangle with border)
    c.setStrokeColor(colors.black)
    c.setLineWidth(1)
    c.rect(
        PDFConfig.LOGO_X,
        PDFConfig.LOGO_Y,
        PDFConfig.LOGO_WIDTH,
        PDFConfig.LOGO_HEIGHT
    )

    # Add "LOGO" text in placeholder
    c.setFont(PDFConfig.FONT_BOLD, 12)
    c.drawCentredString(
        PDFConfig.LOGO_X + PDFConfig.LOGO_WIDTH / 2,
        PDFConfig.LOGO_Y + PDFConfig.LOGO_HEIGHT / 2 - 6,
        "LOGO"
    )

    # Draw company info (right-aligned)
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_SMALL)
    y = PDFConfig.COMPANY_INFO_Y
    for line in PDFConfig.COMPANY_LINES:
        c.drawRightString(PDFConfig.COMPANY_INFO_X, y, line)
        y -= 12

    # Draw title (centered)
    c.setFont(PDFConfig.TITLE_FONT, PDFConfig.TITLE_SIZE)
    c.drawCentredString(
        PDFConfig.PAGE_WIDTH / 2,
        PDFConfig.TITLE_Y,
        PDFConfig.TITLE
    )

    # Return Y position after header
    return PDFConfig.TITLE_Y - 30


def draw_customer_order_info(c: canvas.Canvas, pi_data: PIData, page_num: int, total_pages: int) -> float:
    """
    Draw customer and order information section (first page only).

    Args:
        c: ReportLab canvas
        pi_data: PI data object
        page_num: Current page number
        total_pages: Total number of pages

    Returns:
        Y position after this section
    """
    y = PDFConfig.TITLE_Y - 50

    # Left side: Customer name and address
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT, y, "Messrs. :")

    y -= 15
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)

    # Customer name
    c.drawString(PDFConfig.MARGIN_LEFT + 20, y, pi_data.customer.name)
    y -= 12

    # Customer address (can be multi-line)
    address_lines = pi_data.customer.address.split('\n') if pi_data.customer.address else []
    for addr_line in address_lines:
        if addr_line.strip():
            c.drawString(PDFConfig.MARGIN_LEFT + 20, y, addr_line.strip())
            y -= 12

    # Right side: Order info (right-aligned)
    right_x = PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT
    y_right = PDFConfig.TITLE_Y - 50

    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)

    # Page number
    c.drawRightString(right_x - 60, y_right, "PAGE :")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, str(page_num))
    y_right -= 15

    # Date
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x - 60, y_right, "Date :")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    formatted_date = format_date_invoice(pi_data.master.formatted_date)
    c.drawRightString(right_x, y_right, formatted_date)
    y_right -= 15

    # ORDER (Customer PO)
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x - 60, y_right, "ORDER:")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, pi_data.master.customer_po)
    y_right -= 15

    # Ref. (S/C No)
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x - 60, y_right, "Ref. :")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, pi_data.master.sc_no)
    y_right -= 15

    # Cust# (Customer Code)
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x - 60, y_right, "Cust#:")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, pi_data.customer.code)

    # Return lower of the two Y positions
    return min(y, y_right) - 20


def draw_terms_section(c: canvas.Canvas, pi_data: PIData) -> float:
    """
    Draw payment and shipment terms section.

    Args:
        c: ReportLab canvas
        pi_data: PI data object

    Returns:
        Y position after this section
    """
    y = PDFConfig.TABLE_START_Y_FIRST_PAGE + 40

    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)

    # Payment terms
    c.drawString(PDFConfig.MARGIN_LEFT, y, "Payment :")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT + 80, y, pi_data.master.payment_terms)
    y -= 15

    # Shipment info (using trade_terms as shipment info)
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT, y, "Shipment:")
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT + 80, y, pi_data.master.trade_terms)
    y -= 20

    return y


def draw_line_items_table(
    c: canvas.Canvas,
    pi_data: PIData,
    start_y: float,
    items_to_draw: list,
    currency: str,
    is_last_page: bool
) -> tuple:
    """
    Draw line items table.

    Args:
        c: ReportLab canvas
        pi_data: PI data object
        start_y: Starting Y position
        items_to_draw: List of PIDetail items to draw on this page
        currency: Currency symbol
        is_last_page: Whether this is the last page

    Returns:
        Tuple of (final_y_position, items_drawn_count)
    """
    y = start_y

    # Table column positions
    col_seq = PDFConfig.MARGIN_LEFT
    col_item = col_seq + 40
    col_desc = col_item + 100
    col_qty = col_desc + 200
    col_price = col_qty + 80
    col_amount = col_price + 80

    # Draw table header
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_HEADER)
    c.drawString(col_seq, y, "Seq.")
    c.drawString(col_item, y, "Item No./Cust_Item")
    c.drawString(col_desc, y, "Description")
    c.drawString(col_qty, y, "Quantity")
    c.drawString(col_price, y, "Unit Price")
    c.drawString(col_amount, y, "Amount")

    y -= 12

    # Draw sub-header (trade terms)
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_SMALL)
    trade_terms_line = f"{pi_data.master.trade_terms} ({currency})"
    c.drawString(col_desc, y, trade_terms_line)

    y -= 3

    # Draw header line
    c.setLineWidth(1)
    c.line(PDFConfig.MARGIN_LEFT, y, PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT, y)

    y -= 15

    # Draw items
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    items_drawn = 0

    for detail in items_to_draw:
        # Check if we have space for this item (need at least 40 points)
        if y < PDFConfig.MARGIN_BOTTOM + (PDFConfig.SIGNATURE_HEIGHT if is_last_page else 50):
            break

        # Sequence number
        c.drawString(col_seq, y, str(detail.item_seq))

        # Product code
        c.drawString(col_item, y, detail.product_code)

        # Product description (can be multi-line)
        desc_lines = []
        if detail.product_name_1:
            desc_lines.append(detail.product_name_1)
        if detail.product_name_2:
            desc_lines.append(detail.product_name_2)

        y_desc = y
        for desc_line in desc_lines:
            if y_desc < PDFConfig.MARGIN_BOTTOM + (PDFConfig.SIGNATURE_HEIGHT if is_last_page else 50):
                break
            c.drawString(col_desc, y_desc, desc_line)
            y_desc -= 12

        # Quantity
        qty_str = format_quantity(detail.quantity, detail.unit)
        c.drawString(col_qty, y, qty_str)

        # Unit price
        c.drawRightString(col_price + 70, y, f"{detail.unit_price:,.2f}")

        # Amount
        c.drawRightString(col_amount + 70, y, f"{detail.calculated_amount:,.2f}")

        # Move to next item
        y = y_desc - 5
        items_drawn += 1

    # Draw continuation marker if not last page
    if not is_last_page and items_drawn < len(items_to_draw):
        y -= 10
        c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
        c.drawCentredString(PDFConfig.PAGE_WIDTH / 2, y, "...TO BE CONTINUED...")

    return y, items_drawn


def draw_totals_section(c: canvas.Canvas, pi_data: PIData, currency: str, start_y: float) -> float:
    """
    Draw totals section (last page only).

    Args:
        c: ReportLab canvas
        pi_data: PI data object
        currency: Currency symbol
        start_y: Starting Y position

    Returns:
        Y position after totals
    """
    y = start_y - 20

    # Draw line above totals
    c.setLineWidth(1)
    c.line(PDFConfig.MARGIN_LEFT, y, PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT, y)

    y -= 15

    # Total quantity and amount
    total_qty = sum(d.quantity for d in pi_data.details)
    total_amount = pi_data.calculated_total

    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_HEADER)
    c.drawString(PDFConfig.MARGIN_LEFT + 300, y, "Total:")
    c.drawRightString(PDFConfig.MARGIN_LEFT + 420, y, f"{total_qty:,.0f}")
    c.drawRightString(PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT, y, f"{currency} {total_amount:,.2f}")

    y -= 20

    # Amount in words
    words = amount_to_words(total_amount, currency)
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT, y, f"SAY TOTAL {currency}")
    y -= 12
    c.drawString(PDFConfig.MARGIN_LEFT, y, words)

    y -= 20

    return y


def draw_signature_section(c: canvas.Canvas, pi_data: PIData, total_pages: int, start_y: float):
    """
    Draw signature section (last page only).

    Args:
        c: ReportLab canvas
        pi_data: PI data object
        total_pages: Total number of pages
        start_y: Starting Y position
    """
    y = start_y - 30

    # Left side: Confirmed by customer
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT, y, "Confirmed By")
    y -= 15
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawString(PDFConfig.MARGIN_LEFT, y, pi_data.customer.name)
    y -= 15
    c.drawString(PDFConfig.MARGIN_LEFT, y, "The Authorized")

    # Right side: Company signature
    right_x = PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT
    y_right = start_y - 30

    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, "Your faithfully")
    y_right -= 15
    c.setFont(PDFConfig.FONT_BOLD, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, "FAIRNESS TECHNOLOGY CORP.")
    y_right -= 15
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
    c.drawRightString(right_x, y_right, "_" * 30)
    y_right -= 15
    c.drawRightString(right_x, y_right, "General Manager/Bernard Lin")

    # Total pages at bottom right
    y_bottom = PDFConfig.MARGIN_BOTTOM + 10
    c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_SMALL)
    c.drawRightString(right_x, y_bottom, f"Total Page: {total_pages}")


# ============================================================================
# Main PDF Generation Functions
# ============================================================================

def generate_pi_pdf_bytes(pi_data: PIData) -> bytes:
    """
    Generate PI PDF and return as bytes.

    Args:
        pi_data: PIData object containing all PI information

    Returns:
        PDF content as bytes

    Raises:
        PDFGenerationError: If PDF generation fails or data is invalid
    """
    # Validate input
    if not pi_data:
        raise PDFGenerationError("PIData object is required")

    if not pi_data.is_valid:
        raise PDFGenerationError("PIData object is invalid (missing required fields)")

    if not pi_data.details:
        raise PDFGenerationError("PIData must have at least one detail item")

    try:
        logger.info(f"Generating PDF for S/C {pi_data.master.sc_no}")

        # Create PDF in memory
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=PDFConfig.PAGE_SIZE)

        # Extract currency
        currency = extract_currency_symbol(pi_data.master.trade_terms)

        # Calculate pagination
        # First page: fewer items due to customer info section
        # Continuation pages: more items
        items_per_first_page = 4
        items_per_continuation_page = 6

        total_items = len(pi_data.details)
        items_remaining = total_items

        # Calculate total pages needed
        if items_remaining <= items_per_first_page:
            total_pages = 1
        else:
            items_after_first = items_remaining - items_per_first_page
            continuation_pages = (items_after_first + items_per_continuation_page - 1) // items_per_continuation_page
            total_pages = 1 + continuation_pages

        logger.info(f"PDF will have {total_pages} page(s) for {total_items} items")

        # Generate pages
        page_num = 1
        item_index = 0

        while item_index < total_items:
            # Draw page header
            draw_page_header(c, page_num)

            if page_num == 1:
                # First page: customer info, terms, and line items
                y = draw_customer_order_info(c, pi_data, page_num, total_pages)
                y = draw_terms_section(c, pi_data)

                items_to_draw = pi_data.details[item_index:item_index + items_per_first_page]
                is_last_page = (item_index + len(items_to_draw) >= total_items)

                y, items_drawn = draw_line_items_table(
                    c, pi_data, y, items_to_draw, currency, is_last_page
                )

                if is_last_page:
                    y = draw_totals_section(c, pi_data, currency, y)
                    draw_signature_section(c, pi_data, total_pages, y)

                item_index += items_drawn

            else:
                # Continuation page: just line items (and totals/signature if last)
                items_to_draw = pi_data.details[item_index:item_index + items_per_continuation_page]
                is_last_page = (item_index + len(items_to_draw) >= total_items)

                y = PDFConfig.TABLE_START_Y_CONTINUATION

                # Draw page number (top-right)
                right_x = PDFConfig.PAGE_WIDTH - PDFConfig.MARGIN_RIGHT
                c.setFont(PDFConfig.FONT_NORMAL, PDFConfig.FONT_SIZE_NORMAL)
                c.drawRightString(right_x, PDFConfig.PAGE_HEIGHT - PDFConfig.MARGIN_TOP - 100, f"PAGE : {page_num}")

                y, items_drawn = draw_line_items_table(
                    c, pi_data, y, items_to_draw, currency, is_last_page
                )

                if is_last_page:
                    y = draw_totals_section(c, pi_data, currency, y)
                    draw_signature_section(c, pi_data, total_pages, y)

                item_index += items_drawn

            # Show page and start new one if needed
            c.showPage()
            page_num += 1

        # Finalize PDF
        c.save()

        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()

        logger.info(f"PDF generated successfully ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except PDFGenerationError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error generating PDF: {e}")
        raise PDFGenerationError(f"Failed to generate PDF: {e}")


def generate_pi_pdf(pi_data: PIData, output_path: str) -> str:
    """
    Generate PI PDF and save to file.

    Args:
        pi_data: PIData object containing all PI information
        output_path: Path where PDF should be saved

    Returns:
        Absolute path to the generated PDF file

    Raises:
        PDFGenerationError: If PDF generation or file writing fails
    """
    try:
        # Generate PDF bytes
        pdf_bytes = generate_pi_pdf_bytes(pi_data)

        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        with open(output_file, 'wb') as f:
            f.write(pdf_bytes)

        abs_path = str(output_file.absolute())
        logger.info(f"PDF saved to: {abs_path}")

        return abs_path

    except PDFGenerationError:
        raise
    except Exception as e:
        logger.error(f"Error saving PDF to {output_path}: {e}")
        raise PDFGenerationError(f"Failed to save PDF to {output_path}: {e}")


if __name__ == "__main__":
    # Test the module
    import sys
    from .pi_data import get_pi_data

    print("\n" + "=" * 60)
    print("PDF Generation Module - Test")
    print("=" * 60 + "\n")

    # Get S/C number from command line or use default
    if len(sys.argv) > 1:
        test_sc_no = sys.argv[1]
    else:
        from .pi_data import list_recent_sc_numbers
        recent = list_recent_sc_numbers(5)
        if recent:
            test_sc_no = recent[0]
            print(f"Using recent S/C: {test_sc_no}")
        else:
            print("No S/C numbers found")
            sys.exit(1)

    try:
        # Get PI data
        print(f"Loading PI data for {test_sc_no}...")
        pi_data = get_pi_data(test_sc_no)
        print(f"Loaded: {pi_data.item_count} items, Total: ${pi_data.calculated_total:,.2f}")

        # Generate PDF
        output_path = f"output/PI_{test_sc_no}.pdf"
        print(f"\nGenerating PDF to: {output_path}")

        result_path = generate_pi_pdf(pi_data, output_path)

        print(f"\nSUCCESS! PDF generated:")
        print(f"  Path: {result_path}")

        # Also test bytes generation
        print("\nTesting bytes generation...")
        pdf_bytes = generate_pi_pdf_bytes(pi_data)
        print(f"  Generated {len(pdf_bytes):,} bytes")

        print("\n" + "=" * 60)
        print("Test completed successfully!")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
