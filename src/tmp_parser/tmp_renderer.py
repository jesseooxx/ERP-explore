"""
TMP to PDF Renderer - Renders .tmp files directly to PDF

Uses the layout definition and data from .tmp files to generate PDFs
that match the original ERP output exactly.

The renderer parses the raw_texts data semantically and maps it to
the correct positions based on ERP PDF layout analysis.

Author: Claude Code
"""

import fitz
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import logging
import os
import re

from .parser import (
    TmpReport, PageData, LayoutSection, PlankBlock,
    LabelItem, EditItem, LineItem, ImageItem, FontStyle,
    parse_tmp_file
)

logger = logging.getLogger(__name__)


class PIDataParser:
    """Parses raw_texts from .tmp into structured PI data"""

    def __init__(self, raw_texts: List[str]):
        self.raw_texts = raw_texts
        self.idx = 0

    def parse(self) -> dict:
        """Parse raw_texts into structured data"""
        data = {
            'title': '',
            'date': '',
            'ref': '',
            'customer_name': '',
            'address_lines': [],
            'contact': '',
            'email': '',
            'payment_terms': '',
            'shipment_date': '',
            'trade_terms': '',
            'items': [],
        }

        if not self.raw_texts:
            return data

        # Parse header info
        idx = 0

        # Title (PROFORMA INVOICE)
        if idx < len(self.raw_texts):
            data['title'] = self.raw_texts[idx]
            idx += 1

        # Date
        if idx < len(self.raw_texts):
            data['date'] = self.raw_texts[idx]
            idx += 1

        # Ref (S/C number)
        if idx < len(self.raw_texts):
            data['ref'] = self.raw_texts[idx]
            idx += 1

        # Customer name
        if idx < len(self.raw_texts):
            data['customer_name'] = self.raw_texts[idx]
            idx += 1

        # Address lines (until we hit contact/email/payment)
        while idx < len(self.raw_texts):
            text = self.raw_texts[idx]
            if self._is_contact_or_payment(text):
                break
            data['address_lines'].append(text)
            idx += 1

        # Contact and email
        while idx < len(self.raw_texts):
            text = self.raw_texts[idx]
            if text.startswith('Email:'):
                data['email'] = text
                idx += 1
            elif 'T/T' in text or 'DAYS' in text or 'L/C' in text:
                break
            elif not self._looks_like_product(text):
                data['contact'] = text
                idx += 1
            else:
                break

        # Payment terms
        if idx < len(self.raw_texts) and ('T/T' in self.raw_texts[idx] or 'DAYS' in self.raw_texts[idx] or 'L/C' in self.raw_texts[idx]):
            data['payment_terms'] = self.raw_texts[idx]
            idx += 1

        # Shipment date
        if idx < len(self.raw_texts) and 'Before' in self.raw_texts[idx]:
            data['shipment_date'] = self.raw_texts[idx]
            idx += 1

        # Trade terms
        if idx < len(self.raw_texts) and ('From' in self.raw_texts[idx] or 'FOB' in self.raw_texts[idx] or 'CIF' in self.raw_texts[idx]):
            data['trade_terms'] = self.raw_texts[idx]
            idx += 1

        # Skip table headers
        while idx < len(self.raw_texts):
            text = self.raw_texts[idx]
            if text in ['Item No./Cust_Item', 'Description', 'FOB TAIWAN\'S PORT', '(US$)']:
                idx += 1
            else:
                break

        # Parse items
        data['items'] = self._parse_items(self.raw_texts[idx:])

        return data

    def _is_contact_or_payment(self, text: str) -> bool:
        """Check if text looks like contact info or payment terms"""
        return (
            text.startswith('Email:') or
            'T/T' in text or
            'L/C' in text or
            'DAYS' in text
        )

    def _looks_like_product(self, text: str) -> bool:
        """Check if text looks like a product code"""
        # Product codes: H4D4-5, 6SA1/4-SL, T4D10-15, P4D1-2, etc.
        if not text or len(text) < 4 or len(text) > 15:
            return False

        # Must start with letter or digit
        if not text[0].isalnum():
            return False

        # Must contain a dash (primary separator in product codes)
        if '-' not in text:
            return False

        # Not a specification line (those have colons, spaces at start, or are measurements)
        if ':' in text:
            return False
        if text.startswith('1/4"') or text.startswith('3/8"') or text.startswith('1/2"'):
            return False
        if 'MM' in text.upper() or 'LENGTH' in text.upper():
            return False

        return True

    def _parse_items(self, texts: List[str]) -> List[dict]:
        """Parse product items from remaining texts"""
        raw_items = []
        idx = 0
        current_item = None

        while idx < len(texts):
            text = texts[idx]

            # Skip table headers
            if text in ['Item No./Cust_Item', 'Description', 'FOB TAIWAN\'S PORT', '(US$)']:
                idx += 1
                continue

            # Stop if we hit totals section
            if 'SAY TOTAL' in text or text == 'US$':
                break

            # Check if this looks like a product code
            if self._looks_like_product(text):
                # Save previous item
                if current_item:
                    raw_items.append(current_item)

                current_item = {'code': text, 'name': '', 'specs': [], 'qty': '', 'unit': '', 'price': '', 'amount': ''}
                idx += 1

                # Product name (next non-numeric line)
                if idx < len(texts) and not self._is_numeric(texts[idx]) and not self._looks_like_product(texts[idx]):
                    current_item['name'] = texts[idx]
                    idx += 1

                # Quantity (numeric)
                if idx < len(texts) and self._is_numeric(texts[idx]):
                    current_item['qty'] = texts[idx]
                    idx += 1

                    # Unit
                    if idx < len(texts) and texts[idx] in ['PCS', 'PC', 'SET', 'SETS', 'DOZ', 'BOX']:
                        current_item['unit'] = texts[idx]
                        idx += 1

                    # Price
                    if idx < len(texts) and self._is_numeric(texts[idx]):
                        current_item['price'] = texts[idx]
                        idx += 1

                    # Amount
                    if idx < len(texts) and self._is_numeric(texts[idx]):
                        current_item['amount'] = texts[idx]
                        idx += 1

            # Spec lines
            elif current_item:
                current_item['specs'].append(text)
                idx += 1
            else:
                idx += 1

        # Add last item
        if current_item:
            raw_items.append(current_item)

        # Merge items with same code (continuations from different pages)
        merged = {}
        for item in raw_items:
            code = item['code']
            if code in merged:
                # This is a continuation - merge specs
                existing = merged[code]
                # Add name as spec if it looks like a spec
                if item['name'] and not item['qty']:
                    existing['specs'].append(item['name'])
                existing['specs'].extend(item['specs'])
            else:
                merged[code] = item

        return list(merged.values())

    def _is_numeric(self, text: str) -> bool:
        """Check if text is a number (with commas, decimals)"""
        cleaned = text.replace(',', '').replace('.', '').replace('-', '')
        return cleaned.isdigit()


class TmpToPdfRenderer:
    """Renders TmpReport to PDF using structured data from .tmp file"""

    # Page dimensions (A4 size: 595 x 842)
    PAGE_WIDTH = 595.0
    PAGE_HEIGHT = 842.0

    # === EXACT positions extracted from ERP PDF ===

    # Header image (ERP: x=75.8, y=28.6, size 442.8x84.8)
    HEADER_X = 75.8
    HEADER_Y = 28.6
    HEADER_WIDTH = 442.8
    HEADER_HEIGHT = 84.8

    # Title "PROFORMA INVOICE" (ERP: x=219.4, y=125.3, size=17.6)
    TITLE_X = 219.4
    TITLE_Y = 125.3
    TITLE_SIZE = 17.6

    # Right side labels (PAGE, Date, ORDER, etc.)
    # ERP: x=437.9 for labels, x=472.2 for values
    # y starts at 148.9, spacing ~11.9
    INFO_LABEL_X = 437.9
    INFO_VALUE_X = 472.2
    INFO_Y_START = 148.9
    INFO_LINE_HEIGHT = 11.9

    # Customer info
    # ERP: "Messrs." at x=29.4, y=160.8; values at x=78.2
    CUSTOMER_LABEL_X = 29.4
    CUSTOMER_VALUE_X = 78.2
    CUSTOMER_Y = 160.8

    # Terms (Payment, Shipment)
    # ERP: Payment at y=267.8, Shipment at y=279.7
    TERMS_Y = 267.8
    TERMS_LINE_HEIGHT = 11.9

    # Table header row
    # ERP: y=305.0 for column headers
    TABLE_HEADER_Y = 305.0
    TABLE_SUBHEADER_Y = 319.3  # "FOB TAIWAN'S PORT (US$)"
    TABLE_Y_START = 331.3  # First data row
    TABLE_ROW_HEIGHT = 11.9

    # Column positions (exact from ERP)
    COL_SEQ = 29.4
    COL_ITEM = 58.7
    COL_DESC = 171.2
    COL_QTY = 365.4
    COL_UNIT_PRICE = 468.1
    COL_AMOUNT = 521.9

    # For backwards compatibility
    COL_UNIT = COL_UNIT_PRICE
    COL_PRICE = COL_UNIT_PRICE

    # Font settings (ERP uses ~9.6pt)
    DEFAULT_FONT = "helv"
    FONT_BOLD = "hebo"
    FONT_SIZE = 9.6
    FONT_SIZE_TITLE = 17.6

    def __init__(self, report: TmpReport):
        self.report = report
        self.doc: Optional[fitz.Document] = None
        self.current_page: Optional[fitz.Page] = None
        self.page_number = 0
        self.current_y = 0
        self.item_seq = 0

        # Image search paths
        self.image_paths = [
            Path(__file__).parent.parent.parent / "nrp_backup" / "report_images",
            Path("X:/LEILA/NRP32"),
            Path("Z:/LEILA/NRP32"),
        ]

    def render(self, output_path: Optional[str] = None) -> bytes:
        """Render the report to PDF"""
        self.doc = fitz.open()

        # Use page 2's data as the main data source (page 1 is just title)
        # Page 2 has: header info + some items
        # Pages 3+ have: header info + more items
        if len(self.report.pages) >= 2:
            main_texts = self.report.pages[1].raw_texts
        else:
            main_texts = self.report.pages[0].raw_texts if self.report.pages else []

        # Parse main page data
        parser = PIDataParser(main_texts)
        data = parser.parse()

        # Extract additional items from pages 3+
        for page in self.report.pages[2:]:
            extra_parser = PIDataParser(page.raw_texts)
            extra_data = extra_parser.parse()
            data['items'].extend(extra_data.get('items', []))

        # Render pages
        self._render_document(data)

        # Get PDF bytes
        pdf_bytes = self.doc.tobytes()

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self.doc.save(str(output_path))
            logger.info(f"Saved PDF to {output_path}")

        self.doc.close()
        return pdf_bytes

    def _render_document(self, data: dict):
        """Render complete document with proper pagination"""
        items = data.get('items', [])
        items_per_first_page = 2  # First page has less space
        items_per_page = 3  # Other pages

        # Calculate total pages needed
        if len(items) <= items_per_first_page:
            total_pages = 2  # Items + totals
        else:
            remaining = len(items) - items_per_first_page
            total_pages = 2 + (remaining + items_per_page - 1) // items_per_page

        self.total_pages = total_pages
        item_idx = 0

        for page_num in range(1, total_pages + 1):
            self.page_number = page_num
            self._new_page()

            is_first = (page_num == 1)
            is_last = (page_num == total_pages)

            # Draw header and info on all pages
            self._draw_header_image()
            self._draw_title()
            self._draw_page_info(data, is_first)
            self._draw_customer_info(data, is_first)

            if is_first:
                self._draw_terms(data)

            if not is_last:
                # Draw table header
                self._draw_table_header(data)

                # Draw items for this page
                if is_first:
                    page_items = items[item_idx:item_idx + items_per_first_page]
                    item_idx += items_per_first_page
                else:
                    page_items = items[item_idx:item_idx + items_per_page]
                    item_idx += items_per_page

                for item in page_items:
                    self.item_seq += 1
                    self._draw_item(item)

                self._draw_continuation()
            else:
                # Last page: totals and signature
                self._draw_totals(data)
                self._draw_signature(data)

            self._draw_footer()
            self._draw_standard_lines()

    def _new_page(self):
        """Create a new page"""
        self.current_page = self.doc.new_page(
            width=self.PAGE_WIDTH,
            height=self.PAGE_HEIGHT
        )
        self.current_y = self.TABLE_Y_START

    def _draw_header_image(self):
        """Draw company header image"""
        rect = fitz.Rect(
            self.HEADER_X, self.HEADER_Y,
            self.HEADER_X + self.HEADER_WIDTH,
            self.HEADER_Y + self.HEADER_HEIGHT
        )

        # Find header image
        image_path = self._find_image("htoBCE3878_1_1.jpg")
        if image_path:
            try:
                self.current_page.insert_image(rect, filename=str(image_path))
            except Exception as e:
                logger.warning(f"Failed to insert header image: {e}")

    def _draw_title(self):
        """Draw title with underline"""
        self._draw_text("PROFORMA INVOICE", self.TITLE_X, self.TITLE_Y,
                       font=self.FONT_BOLD, size=self.FONT_SIZE_TITLE)
        # Underline below title
        self._draw_h_line(self.TITLE_X, self.TITLE_X + 170, self.TITLE_Y + 24)

    def _draw_page_info(self, data: dict, is_first: bool):
        """Draw page info on right side"""
        y = self.INFO_Y_START

        self._draw_text("PAGE :", self.INFO_LABEL_X, y)
        self._draw_text(str(self.page_number), 562, y)
        y += self.INFO_LINE_HEIGHT

        self._draw_text("Date :", self.INFO_LABEL_X, y)
        self._draw_text(data.get('date', ''), self.INFO_VALUE_X, y)
        y += self.INFO_LINE_HEIGHT

        if is_first:
            self._draw_text("ORDER:", self.INFO_LABEL_X, y)
            # ORDER number would be in data
            y += self.INFO_LINE_HEIGHT

        self._draw_text("Ref. :", self.INFO_LABEL_X, y)
        self._draw_text(data.get('ref', ''), self.INFO_VALUE_X, y)
        y += self.INFO_LINE_HEIGHT

        if is_first:
            self._draw_text("Cust#:", self.INFO_LABEL_X, y)
            y += self.INFO_LINE_HEIGHT

    def _draw_customer_info(self, data: dict, is_first: bool):
        """Draw customer information"""
        y = self.CUSTOMER_Y

        self._draw_text("Messrs. :", self.CUSTOMER_LABEL_X, y)
        self._draw_text(data.get('customer_name', ''), self.CUSTOMER_VALUE_X, y)
        y += self.INFO_LINE_HEIGHT

        if is_first:
            # Address lines
            for line in data.get('address_lines', [])[:5]:
                self._draw_text(line, self.CUSTOMER_VALUE_X, y)
                y += self.INFO_LINE_HEIGHT

            # Contact
            if data.get('contact'):
                self._draw_text(data['contact'], self.CUSTOMER_VALUE_X, y)
                y += self.INFO_LINE_HEIGHT

            # Email
            if data.get('email'):
                self._draw_text(data['email'], self.CUSTOMER_VALUE_X, y)
                y += self.INFO_LINE_HEIGHT

    def _draw_terms(self, data: dict):
        """Draw payment and shipment terms"""
        y = self.TERMS_Y

        self._draw_text("Payment :", self.CUSTOMER_LABEL_X, y)
        self._draw_text(data.get('payment_terms', ''), self.CUSTOMER_VALUE_X, y)
        y += self.INFO_LINE_HEIGHT

        self._draw_text("Shipment:", self.CUSTOMER_LABEL_X, y)
        self._draw_text(data.get('shipment_date', ''), self.CUSTOMER_VALUE_X, y)
        y += self.INFO_LINE_HEIGHT

        self._draw_text(data.get('trade_terms', ''), self.CUSTOMER_VALUE_X, y)

    def _draw_table_header(self, data: dict):
        """Draw table header"""
        # ERP draws column headers at y=305.0
        y = self.TABLE_HEADER_Y
        self._draw_text("Seq.", self.COL_SEQ, y)
        self._draw_text("Item No./Cust_Item", self.COL_ITEM, y)
        self._draw_text("Description", self.COL_DESC, y)
        self._draw_text("Quantity", 360.5, y)  # ERP uses 360.5 for header
        self._draw_text("Unit Price", 443.6, y)  # ERP uses 443.6 for header
        self._draw_text("Amount", 536.6, y)  # ERP uses 536.6 for header

        # Trade terms subheader at y=319.3
        y = self.TABLE_SUBHEADER_Y
        trade = data.get('trade_terms', 'FOB TAIWAN')
        if 'FOB' in trade:
            self._draw_text("FOB TAIWAN'S PORT", 408.6, y)  # ERP position
            self._draw_text("(US$)", 543.9, y)  # ERP position
        else:
            trade_short = trade.split()[0] if trade else ''
            self._draw_text(f"{trade_short} (US$)", 408.6, y)

    def _draw_item(self, item: dict):
        """Draw a single line item with specs"""
        y = self.current_y

        # Sequence
        self._draw_text(str(self.item_seq), self.COL_SEQ, y)

        # Product code
        self._draw_text(item.get('code', ''), self.COL_ITEM, y)

        # Product name
        self._draw_text(item.get('name', '')[:35], self.COL_DESC, y)

        # Quantity
        self._draw_text(item.get('qty', ''), self.COL_QTY, y)

        # Unit
        self._draw_text(item.get('unit', ''), self.COL_UNIT, y)

        # Price
        self._draw_text(item.get('price', ''), self.COL_PRICE, y)

        # Amount
        self._draw_text(item.get('amount', ''), self.COL_AMOUNT, y)

        y += self.TABLE_ROW_HEIGHT

        # Specs (multiple lines)
        for spec in item.get('specs', []):
            self._draw_text(spec[:70], self.COL_DESC, y, size=10)
            y += self.TABLE_ROW_HEIGHT

        self.current_y = y + 5

    def _draw_continuation(self):
        """Draw continuation marker"""
        y = self.PAGE_HEIGHT - 50
        self._draw_text("...TO BE CONTINUED...", self.PAGE_WIDTH / 2 - 60, y)

    def _draw_totals(self, data: dict):
        """Draw totals section"""
        y = self.TABLE_Y_START

        # Calculate totals
        items = data.get('items', [])
        total_qty = 0
        total_amount = 0.0

        for item in items:
            try:
                qty = float(item.get('qty', '0').replace(',', ''))
                total_qty += qty
            except:
                pass
            try:
                amt = float(item.get('amount', '0').replace(',', ''))
                total_amount += amt
            except:
                pass

        # Total line
        self._draw_h_line(1, self.PAGE_WIDTH - 1, y - 10)
        self._draw_text("Total:", self.COL_SEQ, y, font=self.FONT_BOLD)
        self._draw_text(f"{total_qty:,.0f}PCS", self.COL_QTY, y)
        self._draw_text(f"US$ {total_amount:,.2f}", self.COL_AMOUNT, y, font=self.FONT_BOLD)

        y += self.TABLE_ROW_HEIGHT * 2

        # SAY TOTAL
        amount_words = self._amount_to_words(total_amount)
        self._draw_text(f"SAY TOTAL U.S DOLLAR {amount_words} ONLY.", self.COL_SEQ, y)

        self.current_y = y + self.TABLE_ROW_HEIGHT * 3

    def _draw_signature(self, data: dict):
        """Draw signature section"""
        y = self.PAGE_HEIGHT - 140

        # Left side - Customer
        self._draw_text("Confirmed By", self.COL_SEQ, y)
        self._draw_text(data.get('customer_name', ''), self.COL_SEQ, y + 16)
        self._draw_h_line(self.COL_SEQ, 200, y + 55)
        self._draw_text("The Authorized", self.COL_SEQ, y + 60)

        # Right side - Company
        right_x = 380
        self._draw_text("Your faithfully", right_x, y)
        self._draw_text("FAIRNESS TECHNOLOGY CORP.", right_x, y + 16)
        self._draw_h_line(right_x, self.PAGE_WIDTH - 20, y + 55)
        self._draw_text("General Manager/Bernard Lin", right_x, y + 60)

    def _draw_footer(self):
        """Draw page footer"""
        footer_y = self.PAGE_HEIGHT - 16
        self._draw_h_line(1, self.PAGE_WIDTH - 1, footer_y)
        y = self.PAGE_HEIGHT - 12
        self._draw_text(f"Total Page: {self.total_pages}", self.PAGE_WIDTH - 80, y)

    def _draw_standard_lines(self):
        """Lines are now drawn in context"""
        pass

    def _draw_text(self, text: str, x: float, y: float,
                   font: str = None, size: float = None):
        """
        Draw text on current page.

        Note: y is the TOP of the text bounding box (matching ERP PDF coordinates).
        PyMuPDF insert_text uses baseline, so we add size to y.
        """
        if not text:
            return

        font = font or self.DEFAULT_FONT
        size = size or self.FONT_SIZE

        try:
            # ERP coordinates are at text top, convert to baseline
            baseline_y = y + size
            self.current_page.insert_text(
                (x, baseline_y),
                text,
                fontname=font,
                fontsize=size,
                color=(0, 0, 0)
            )
        except Exception as e:
            logger.warning(f"Failed to draw text '{text[:20]}': {e}")

    def _draw_h_line(self, x1: float, x2: float, y: float, width: float = 0.5):
        """Draw a horizontal line"""
        shape = self.current_page.new_shape()
        shape.draw_line(fitz.Point(x1, y), fitz.Point(x2, y))
        shape.finish(color=(0, 0, 0), width=width)
        shape.commit()

    def _find_image(self, filename: str) -> Optional[Path]:
        """Find image file"""
        for search_path in self.image_paths:
            full_path = search_path / filename
            if full_path.exists():
                return full_path
        return None

    def _amount_to_words(self, amount: float) -> str:
        """Convert amount to words"""
        try:
            from num2words import num2words
            dollars = int(amount)
            words = num2words(dollars).upper()
            words = words.replace("-", " ").replace(",", "")
            return words
        except:
            return f"{amount:,.2f}"


def render_tmp_to_pdf(tmp_path: str, output_path: Optional[str] = None) -> bytes:
    """
    Render a .tmp file directly to PDF.

    Args:
        tmp_path: Path to the .tmp file
        output_path: Optional path to save the PDF

    Returns:
        PDF content as bytes
    """
    report = parse_tmp_file(tmp_path)
    renderer = TmpToPdfRenderer(report)
    return renderer.render(output_path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python tmp_renderer.py <file.tmp> [output.pdf]")
        sys.exit(1)

    tmp_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output.pdf"

    print(f"Rendering {tmp_path} -> {output_path}")
    pdf_bytes = render_tmp_to_pdf(tmp_path, output_path)
    print(f"Generated {len(pdf_bytes):,} bytes")
