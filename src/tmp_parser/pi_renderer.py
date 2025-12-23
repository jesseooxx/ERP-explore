"""
PI PDF Renderer - Generates PI PDFs matching ERP layout exactly

Uses PyMuPDF to render PDFs with the same layout as ERP-generated documents.
Takes PIData from database query and renders it using extracted ERP templates.

Author: Claude Code
"""

import fitz
from pathlib import Path
from typing import Optional, List, Tuple
from datetime import datetime
import logging
import os

# Import PI data structures
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from pi_generator.pi_data import PIData, PIDetail

logger = logging.getLogger(__name__)


class PIRenderer:
    """Renders PI documents matching ERP layout"""

    # Page dimensions (matches ERP exactly: 668 x 872)
    PAGE_WIDTH = 668.0
    PAGE_HEIGHT = 872.0

    # Layout constants from ERP PDF analysis
    MARGIN_LEFT = 4
    MARGIN_RIGHT = 667
    MARGIN_TOP = 125

    # Header image position (from ERP analysis)
    HEADER_X = 59
    HEADER_Y = 2
    HEADER_WIDTH = 548
    HEADER_HEIGHT = 105

    # Header positions
    TITLE_X = 238
    TITLE_Y = 126
    TITLE_SIZE = 24.0
    TITLE_UNDERLINE_Y = 151

    # Page info positions (right side, from ERP analysis)
    INFO_LABEL_X = 505
    INFO_VALUE_X = 547
    INFO_Y_START = 153
    INFO_LINE_HEIGHT = 15

    # Customer info position
    CUSTOMER_X = 4
    CUSTOMER_Y = 168
    CUSTOMER_VALUE_X = 64

    # Table positions
    TABLE_HEADER_LINE_Y = 331
    TABLE_SUBHEADER_LINE_Y = 350
    TABLE_Y_START = 365
    TABLE_ROW_HEIGHT = 15

    # Column positions (from ERP analysis)
    COL_SEQ = 10
    COL_ITEM = 55
    COL_DESC = 160
    COL_QTY = 420
    COL_UNIT = 470
    COL_PRICE = 530
    COL_AMOUNT = 600

    # Footer line position
    FOOTER_LINE_Y = 856

    # Font settings (ERP uses 12pt font)
    FONT_NORMAL = "helv"
    FONT_BOLD = "hebo"
    FONT_SIZE = 12.0
    FONT_SIZE_TITLE = 24.0

    def __init__(self, pi_data: PIData):
        self.pi_data = pi_data
        self.doc: Optional[fitz.Document] = None
        self.current_page: Optional[fitz.Page] = None
        self.page_count = 0
        self.current_y = 0

        # Header image path
        self.header_image_path = self._find_header_image()

    def _find_header_image(self) -> Optional[str]:
        """Find the company header image"""
        possible_paths = [
            Path(__file__).parent.parent.parent / "nrp_backup" / "report_images" / "htoBCE3878_1_1.jpg",
            Path(__file__).parent.parent.parent / "assets" / "header.jpg",
        ]
        for p in possible_paths:
            if p.exists():
                return str(p)
        return None

    def render(self, output_path: Optional[str] = None) -> bytes:
        """
        Render the PI document to PDF.

        Args:
            output_path: Optional path to save the PDF

        Returns:
            PDF content as bytes
        """
        self.doc = fitz.open()
        self.page_count = 0

        # Calculate how many items fit per page (matching ERP pagination)
        items_first_page = 3  # First page has header, customer info, terms
        items_per_page = 4    # Subsequent pages (ERP shows fewer per page)

        details = self.pi_data.details
        total_items = len(details)

        # Render pages (ERP puts totals on a separate last page)
        if total_items == 0:
            self._render_page([], is_first=True, is_last=True)
        else:
            item_idx = 0
            while item_idx < total_items:
                is_first = (item_idx == 0)

                # Determine items for this page
                if is_first:
                    page_items = details[item_idx:item_idx + items_first_page]
                    item_idx += items_first_page
                else:
                    page_items = details[item_idx:item_idx + items_per_page]
                    item_idx += items_per_page

                is_last_items = (item_idx >= total_items)
                # Items pages are never the last page (totals go on separate page)
                self._render_page(page_items, is_first=is_first, is_last=False)

            # Render final page with totals and signature
            self._render_page([], is_first=False, is_last=True)

        # Get PDF bytes
        pdf_bytes = self.doc.tobytes()

        # Save if path provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self.doc.save(str(output_path))
            logger.info(f"Saved PDF to {output_path}")

        self.doc.close()
        return pdf_bytes

    def _render_page(self, items: List[PIDetail], is_first: bool, is_last: bool):
        """Render a single page"""
        self.page_count += 1
        self.current_page = self.doc.new_page(
            width=self.PAGE_WIDTH,
            height=self.PAGE_HEIGHT
        )
        self.current_y = self.MARGIN_TOP

        # Draw header image
        self._draw_header_image()

        # Draw title
        self._draw_title()

        # Draw page info (right side)
        self._draw_page_info(is_first)

        # Draw customer info (first page only has full info)
        self._draw_customer_info(is_first)

        # Draw terms (first page)
        if is_first:
            self._draw_terms()

        # For pages with items, draw table header and items
        if items:
            # Draw table header
            self._draw_table_header()

            # Draw line items
            for item in items:
                self._draw_line_item(item)

            # Draw continuation marker for non-last pages
            if not is_last:
                self._draw_continuation()

        # Last page: draw totals and signature
        if is_last:
            self.current_y = self.TABLE_Y_START  # Reset to table area
            self._draw_totals()
            self._draw_signature()

        # Draw page footer
        self._draw_footer()

    def _draw_header_image(self):
        """Draw company header image (matches ERP position)"""
        if self.header_image_path and os.path.exists(self.header_image_path):
            rect = fitz.Rect(
                self.HEADER_X, self.HEADER_Y,
                self.HEADER_X + self.HEADER_WIDTH,
                self.HEADER_Y + self.HEADER_HEIGHT
            )
            try:
                self.current_page.insert_image(rect, filename=self.header_image_path)
            except Exception as e:
                logger.warning(f"Failed to insert header image: {e}")

    def _draw_title(self):
        """Draw PROFORMA INVOICE title with underline"""
        self._draw_text(
            "PROFORMA INVOICE",
            self.TITLE_X, self.TITLE_Y,
            font=self.FONT_BOLD,
            size=self.FONT_SIZE_TITLE,
            underline=False  # We draw a proper underline at the exact position
        )
        # Draw underline at exact ERP position
        self._draw_line(self.TITLE_X, self.TITLE_UNDERLINE_Y, 430, self.TITLE_UNDERLINE_Y)

    def _draw_page_info(self, is_first: bool):
        """Draw page info on right side (matches ERP layout)"""
        y = self.INFO_Y_START
        lh = self.INFO_LINE_HEIGHT

        # PAGE (label at 505, value at 562)
        self._draw_text("PAGE :", self.INFO_LABEL_X, y, size=self.FONT_SIZE)
        self._draw_text(str(self.page_count), 562, y, size=self.FONT_SIZE)
        y += lh

        # Date (label at 505, value at 547)
        self._draw_text("Date :", self.INFO_LABEL_X, y, size=self.FONT_SIZE)
        date_str = self._format_date(self.pi_data.master.create_date)
        self._draw_text(date_str, self.INFO_VALUE_X, y, size=self.FONT_SIZE)
        y += lh

        if is_first:
            # ORDER (label at 505, value at 547)
            self._draw_text("ORDER:", self.INFO_LABEL_X, y, size=self.FONT_SIZE)
            self._draw_text(self.pi_data.master.customer_po, self.INFO_VALUE_X, y, size=self.FONT_SIZE)
            y += lh

        # Ref (label at 505, value at 547)
        self._draw_text("Ref. :", self.INFO_LABEL_X, y, size=self.FONT_SIZE)
        self._draw_text(self.pi_data.master.sc_no, self.INFO_VALUE_X, y, size=self.FONT_SIZE)
        y += lh

        if is_first:
            # Cust# (label at 505, value at 547)
            self._draw_text("Cust#:", self.INFO_LABEL_X, y, size=self.FONT_SIZE)
            self._draw_text(self.pi_data.customer.code, self.INFO_VALUE_X, y, size=self.FONT_SIZE)
            y += lh

    def _draw_customer_info(self, is_first: bool):
        """Draw customer information (matches ERP layout)"""
        y = self.CUSTOMER_Y

        # Messrs. line (label at 4, value at 64)
        self._draw_text("Messrs. :", self.CUSTOMER_X, y, size=self.FONT_SIZE)
        self._draw_text(self.pi_data.customer.name, self.CUSTOMER_VALUE_X, y, size=self.FONT_SIZE)
        y += self.TABLE_ROW_HEIGHT

        if is_first:
            # Address lines (at x=64)
            address_lines = self.pi_data.customer.address.split('\n') if self.pi_data.customer.address else []
            for line in address_lines[:5]:  # Max 5 lines
                self._draw_text(line.strip(), self.CUSTOMER_VALUE_X, y, size=self.FONT_SIZE)
                y += self.TABLE_ROW_HEIGHT

    def _draw_terms(self):
        """Draw payment and shipment terms (matches ERP layout)"""
        y = 273

        # Payment (at x=4, value at x=64)
        self._draw_text("Payment :", self.CUSTOMER_X, y, size=self.FONT_SIZE)
        self._draw_text(self.pi_data.master.payment_terms, self.CUSTOMER_VALUE_X, y, size=self.FONT_SIZE)
        y += self.TABLE_ROW_HEIGHT

        # Shipment
        self._draw_text("Shipment:", self.CUSTOMER_X, y, size=self.FONT_SIZE)
        y += self.TABLE_ROW_HEIGHT

        # Trade terms
        self._draw_text(self.pi_data.master.trade_terms, self.CUSTOMER_VALUE_X, y, size=self.FONT_SIZE)

        self.current_y = y + 30

    def _draw_table_header(self):
        """Draw table header row (matches ERP layout with horizontal lines)"""
        # Draw first horizontal line (at y=331 in ERP)
        self._draw_line(1, self.TABLE_HEADER_LINE_Y, self.MARGIN_RIGHT, self.TABLE_HEADER_LINE_Y)

        # Column headers (between the two lines)
        y = self.TABLE_HEADER_LINE_Y + 5
        self._draw_text("Seq.", self.COL_SEQ, y, size=self.FONT_SIZE)
        self._draw_text("Item No./Cust_Item", self.COL_ITEM, y, size=self.FONT_SIZE)
        self._draw_text("Description", self.COL_DESC, y, size=self.FONT_SIZE)
        self._draw_text("Quantity", self.COL_QTY, y, size=self.FONT_SIZE)
        self._draw_text("Unit Price", self.COL_PRICE, y, size=self.FONT_SIZE)
        self._draw_text("Amount", self.COL_AMOUNT, y, size=self.FONT_SIZE)

        # Draw second horizontal line (at y=350 in ERP)
        self._draw_line(1, self.TABLE_SUBHEADER_LINE_Y, self.MARGIN_RIGHT, self.TABLE_SUBHEADER_LINE_Y)

        # Trade terms subheader
        y = self.TABLE_SUBHEADER_LINE_Y + 5
        terms_text = f"{self.pi_data.master.trade_terms} (US$)"
        self._draw_text(terms_text, self.COL_PRICE - 30, y, size=self.FONT_SIZE)

        self.current_y = self.TABLE_Y_START

    def _draw_line_item(self, item: PIDetail):
        """Draw a single line item (matches ERP layout)"""
        y = self.current_y

        # Sequence number
        self._draw_text(str(item.item_seq), self.COL_SEQ, y, size=self.FONT_SIZE)

        # Product code
        self._draw_text(item.product_code, self.COL_ITEM, y, size=self.FONT_SIZE)

        # Description (first line, max 35 chars to fit column)
        desc = item.full_product_name
        self._draw_text(desc[:35], self.COL_DESC, y, size=self.FONT_SIZE)

        # Quantity with unit
        qty_str = f"{item.quantity:,.0f} {item.unit}"
        self._draw_text(qty_str, self.COL_QTY, y, size=self.FONT_SIZE)

        # Unit price
        price_str = f"{item.unit_price:.3f}"
        self._draw_text(price_str, self.COL_PRICE, y, size=self.FONT_SIZE)

        # Amount
        amount = item.calculated_amount
        amount_str = f"{amount:,.3f}"
        self._draw_text(amount_str, self.COL_AMOUNT, y, size=self.FONT_SIZE)

        # Add extra lines for longer descriptions if needed
        if len(desc) > 35:
            y += self.TABLE_ROW_HEIGHT
            self._draw_text(desc[35:70], self.COL_DESC, y, size=self.FONT_SIZE)

        self.current_y = y + self.TABLE_ROW_HEIGHT * 2

    def _draw_totals(self):
        """Draw totals section (matches ERP layout)"""
        y = self.current_y + 20

        # Draw line above totals
        self._draw_line(1, y, self.MARGIN_RIGHT, y)
        y += self.TABLE_ROW_HEIGHT

        # Total line
        self._draw_text("Total:", self.COL_SEQ, y, size=self.FONT_SIZE, font=self.FONT_BOLD)

        # Total quantity
        total_qty = sum(d.quantity for d in self.pi_data.details)
        self._draw_text(f"{total_qty:,.0f}PCS", self.COL_QTY, y, size=self.FONT_SIZE)

        # Total amount
        total_str = f"US$ {self.pi_data.calculated_total:,.2f}"
        self._draw_text(total_str, self.COL_AMOUNT, y, size=self.FONT_SIZE, font=self.FONT_BOLD)

        y += self.TABLE_ROW_HEIGHT * 2

        # SAY TOTAL
        amount_words = self._amount_to_words(self.pi_data.calculated_total)
        say_total = f"SAY TOTAL U.S DOLLAR {amount_words} ONLY."
        self._draw_text(say_total, self.COL_SEQ, y, size=self.FONT_SIZE)

        self.current_y = y + self.TABLE_ROW_HEIGHT * 3

    def _draw_continuation(self):
        """Draw continuation marker"""
        y = self.PAGE_HEIGHT - 50
        self._draw_text("...TO BE CONTINUED...", self.PAGE_WIDTH / 2 - 60, y, size=self.FONT_SIZE)

    def _draw_signature(self):
        """Draw signature section (matches ERP layout)"""
        y = self.PAGE_HEIGHT - 150

        # Left side - Customer
        self._draw_text("Confirmed By", self.COL_SEQ, y, size=self.FONT_SIZE)
        self._draw_text(self.pi_data.customer.name, self.COL_SEQ, y + 18, size=self.FONT_SIZE)
        self._draw_line(self.COL_SEQ, y + 60, 220, y + 60)
        self._draw_text("The Authorized", self.COL_SEQ, y + 65, size=self.FONT_SIZE)

        # Right side - Company
        right_x = 420
        self._draw_text("Your faithfully", right_x, y, size=self.FONT_SIZE)
        self._draw_text("FAIRNESS TECHNOLOGY CORP.", right_x, y + 18, size=self.FONT_SIZE)
        self._draw_line(right_x, y + 60, self.MARGIN_RIGHT - 20, y + 60)
        self._draw_text("General Manager/Bernard Lin", right_x, y + 65, size=self.FONT_SIZE)

    def _draw_footer(self):
        """Draw page footer (matches ERP layout)"""
        # Draw footer line on every page
        self._draw_line(1, self.FOOTER_LINE_Y, self.MARGIN_RIGHT, self.FOOTER_LINE_Y)

        y = self.PAGE_HEIGHT - 12
        total_pages = self._estimate_total_pages()
        self._draw_text(f"Total Page: {total_pages}", self.MARGIN_RIGHT - 100, y, size=self.FONT_SIZE)

    def _estimate_total_pages(self) -> int:
        """Estimate total number of pages (including separate totals page)"""
        total_items = len(self.pi_data.details)
        if total_items == 0:
            return 1

        # First page has 3 items
        if total_items <= 3:
            return 2  # Items page + totals page

        remaining = total_items - 3
        item_pages = 1 + (remaining + 3) // 4  # Ceiling division with 4 items per page
        return item_pages + 1  # Add totals page

    def _draw_text(self, text: str, x: float, y: float,
                   font: str = None, size: float = None,
                   align: str = "left", underline: bool = False):
        """Draw text on current page"""
        if not text:
            return

        font = font or self.FONT_NORMAL
        size = size or self.FONT_SIZE

        # Adjust x for alignment
        if align == "right":
            text_width = fitz.get_text_length(text, fontname=font, fontsize=size)
            x = x - text_width
        elif align == "center":
            text_width = fitz.get_text_length(text, fontname=font, fontsize=size)
            x = x - text_width / 2

        try:
            self.current_page.insert_text(
                (x, y + size),  # PyMuPDF uses baseline y
                text,
                fontname=font,
                fontsize=size,
                color=(0, 0, 0)
            )

            if underline:
                # Draw underline
                text_width = fitz.get_text_length(text, fontname=font, fontsize=size)
                self._draw_line(x, y + size + 2, x + text_width, y + size + 2)

        except Exception as e:
            logger.warning(f"Failed to draw text '{text[:20]}': {e}")

    def _draw_line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5):
        """Draw a line on current page"""
        shape = self.current_page.new_shape()
        shape.draw_line(fitz.Point(x1, y1), fitz.Point(x2, y2))
        shape.finish(color=(0, 0, 0), width=width)
        shape.commit()

    def _format_date(self, date_str: str) -> str:
        """Format date string from YYYYMMDD to MMM. DD, YYYY"""
        if not date_str or len(date_str) != 8:
            return date_str or ""

        try:
            year = date_str[:4]
            month = int(date_str[4:6])
            day = int(date_str[6:8])

            months = ["", "JAN.", "FEB.", "MAR.", "APR.", "MAY", "JUN.",
                     "JUL.", "AUG.", "SEP.", "OCT.", "NOV.", "DEC."]

            return f"{months[month]} {day}, {year}"
        except:
            return date_str

    def _amount_to_words(self, amount: float) -> str:
        """Convert amount to words"""
        try:
            from num2words import num2words
            dollars = int(amount)
            cents = int((amount - dollars) * 100)

            words = num2words(dollars).upper()
            words = words.replace("-", " ").replace(",", "")

            if cents > 0:
                return f"{words} AND {cents:02d}/100"
            return words
        except ImportError:
            return f"{amount:,.2f}"
        except Exception as e:
            logger.warning(f"Failed to convert amount to words: {e}")
            return f"{amount:,.2f}"


def render_pi_pdf(pi_data: PIData, output_path: Optional[str] = None) -> bytes:
    """
    Convenience function to render PI data to PDF.

    Args:
        pi_data: PI data from database query
        output_path: Optional path to save the PDF

    Returns:
        PDF content as bytes
    """
    renderer = PIRenderer(pi_data)
    return renderer.render(output_path)


if __name__ == "__main__":
    # Test with database data
    from pi_generator.pi_data import get_pi_data

    print("Fetching PI data...")
    pi_data = get_pi_data("T17104")

    print(f"Rendering PDF for S/C {pi_data.master.sc_no}...")
    output_path = "output/PI_rendered_T17104.pdf"
    pdf_bytes = render_pi_pdf(pi_data, output_path)

    print(f"Generated {len(pdf_bytes):,} bytes")
    print(f"Saved to: {output_path}")
