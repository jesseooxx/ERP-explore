"""
PDF Renderer - Renders Datawin reports to PDF
Compatible with nrp32.exe rendering pipeline
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PIL import Image as PILImage
import os
from typing import Tuple, Optional

from .parser import (
    ReportDocument, ReportElement, PlankElement, LabelElement,
    EditElement, LineElement, ImageElement, FontElement, HeadElement, PSFlags
)


class PDFRenderer:
    """
    Renders Datawin Report to PDF format

    Coordinate System Conversion:
    - Datawin units: 0.1mm (estimated based on analysis)
    - ReportLab units: points (1/72 inch)
    - Conversion: datawin_units * 0.1mm * (72/25.4) points/mm
    """

    # Coordinate conversion factor
    DW_TO_POINTS = 0.1 * (72 / 25.4)  # ~0.283 points per datawin unit

    def __init__(self, page_size=A4, margin: float = 10*mm):
        """
        Initialize PDF renderer

        Args:
            page_size: ReportLab page size (A4, letter, etc.)
            margin: Page margin in points
        """
        self.page_size = page_size
        self.margin = margin
        self.canvas = None

        # Current rendering state
        self.current_font_name = "Helvetica"
        self.current_font_size = 12
        self.current_font_bold = False
        self.current_font_underline = False

    def render(self, document: ReportDocument, output_path: str):
        """
        Render document to PDF file

        Args:
            document: ReportDocument to render
            output_path: Output PDF file path
        """
        # Create canvas
        self.canvas = canvas.Canvas(output_path, pagesize=self.page_size)

        # Set metadata
        if document.title:
            self.canvas.setTitle(document.title)
        self.canvas.setAuthor("Datawin Renderer")
        self.canvas.setSubject("Datawin Report")

        # Render page
        self._render_page(document)

        # Save PDF
        self.canvas.save()
        print(f"PDF saved to: {output_path}")

    def _render_page(self, document: ReportDocument):
        """Render a single page"""

        # Get page dimensions
        page_width, page_height = self.page_size

        # Render HEAD if exists
        head = document.get_head()
        if head:
            self._render_head(head, page_width, page_height)

        # Render all PLANKs and elements
        for elem in document.elements:
            if isinstance(elem, PlankElement):
                self._render_plank(elem, 0, 0, page_height)
            elif isinstance(elem, FontElement):
                self._apply_font(elem)
            elif not isinstance(elem, HeadElement):
                # Render top-level elements (rare, most are in PLANKs)
                self._render_element(elem, 0, 0, page_height)

        # Finalize page
        self.canvas.showPage()

    def _render_head(self, head: HeadElement, page_width: float, page_height: float):
        """Render page header"""
        if not head:
            return

        flags = head.get_style_flag_value()

        # Calculate header rectangle
        head_height = head.head_size * self.DW_TO_POINTS
        x = self.margin
        y = page_height - self.margin - head_height
        width = page_width - 2 * self.margin

        # Draw border if requested
        if flags & PSFlags.PS_BORDER:
            self.canvas.setStrokeColor(colors.black)
            self.canvas.setLineWidth(1)
            self.canvas.rect(x, y, width, head_height, stroke=1, fill=0)

        # Draw shadow if requested
        if flags & PSFlags.PS_SHADOW:
            shadow_offset = 3
            self.canvas.setStrokeColor(colors.gray)
            self.canvas.setFillColor(colors.lightgrey)
            self.canvas.rect(x + shadow_offset, y - shadow_offset,
                           width, head_height, stroke=1, fill=1)

    def _render_plank(self, plank: PlankElement, base_x: float,
                     base_y: float, page_height: float):
        """
        Render a PLANK container and its children

        Args:
            plank: PlankElement to render
            base_x: Base X offset in points
            base_y: Base Y offset in points
            page_height: Page height for Y coordinate conversion
        """
        # Convert PLANK position to PDF coordinates
        plank_x = self.margin + base_x + (plank.x * self.DW_TO_POINTS)
        plank_y = base_y + (plank.y * self.DW_TO_POINTS)

        # Render children
        for child in plank.children:
            self._render_element(child, plank_x, plank_y, page_height)

    def _render_element(self, elem: ReportElement, base_x: float,
                       base_y: float, page_height: float):
        """Render a single element"""

        if isinstance(elem, LabelElement):
            self._render_label(elem, base_x, base_y, page_height)
        elif isinstance(elem, EditElement):
            self._render_edit(elem, base_x, base_y, page_height)
        elif isinstance(elem, LineElement):
            self._render_line(elem, base_x, base_y, page_height)
        elif isinstance(elem, ImageElement):
            self._render_image(elem, base_x, base_y, page_height)

    def _render_label(self, label: LabelElement, base_x: float,
                     base_y: float, page_height: float):
        """Render static text label"""
        self._render_text(label.text, label, base_x, base_y, page_height)

    def _render_edit(self, edit: EditElement, base_x: float,
                    base_y: float, page_height: float):
        """Render EDIT field (with bound data)"""
        text = edit.bound_data if edit.bound_data else f"[EDIT_{edit.id_num}]"
        self._render_text(text, edit, base_x, base_y, page_height)

    def _render_text(self, text: str, elem: ReportElement,
                    base_x: float, base_y: float, page_height: float):
        """
        Render text with alignment and styling

        Args:
            text: Text to render
            elem: Element containing styling info
            base_x: Base X coordinate in points
            base_y: Base Y coordinate in points
            page_height: Page height for Y inversion
        """
        if not text:
            return

        # Convert coordinates (Y is inverted in PDF)
        x = base_x + (elem.x * self.DW_TO_POINTS)
        # PDF Y coordinates: 0 at bottom, we want Y to grow downward from top
        y = page_height - self.margin - base_y - (elem.y * self.DW_TO_POINTS) - (elem.height * self.DW_TO_POINTS)

        # Apply current font
        font_name = self.current_font_name
        font_size = self.current_font_size

        # Handle bold
        if self.current_font_bold:
            if "Helvetica" in font_name:
                font_name = "Helvetica-Bold"
            elif "Times" in font_name:
                font_name = "Times-Bold"

        self.canvas.setFont(font_name, font_size)

        # Get text width for alignment
        text_width = self.canvas.stringWidth(text, font_name, font_size)
        elem_width = elem.width * self.DW_TO_POINTS

        # Calculate alignment offset
        flags = elem.get_style_flag_value()
        x_offset = 0
        if flags & PSFlags.PS_CENTER:
            x_offset = (elem_width - text_width) / 2
        elif flags & PSFlags.PS_RIGHT:
            x_offset = elem_width - text_width

        # Draw text
        self.canvas.drawString(x + x_offset, y, text)

        # Draw underline if requested
        if self.current_font_underline:
            underline_y = y - 2
            self.canvas.line(x + x_offset, underline_y,
                           x + x_offset + text_width, underline_y)

    def _render_line(self, line: LineElement, base_x: float,
                    base_y: float, page_height: float):
        """Render a line"""
        # Convert coordinates
        x1 = base_x + (line.x * self.DW_TO_POINTS)
        y1 = page_height - self.margin - base_y - (line.y * self.DW_TO_POINTS)
        x2 = base_x + (line.x2 * self.DW_TO_POINTS)
        y2 = page_height - self.margin - base_y - (line.y2 * self.DW_TO_POINTS)

        # Set line style
        self.canvas.setLineWidth(line.thickness * 0.5)  # Scale thickness
        self.canvas.setStrokeColor(colors.black)

        # Draw line
        self.canvas.line(x1, y1, x2, y2)

    def _render_image(self, img_elem: ImageElement, base_x: float,
                     base_y: float, page_height: float):
        """Render an image"""
        # Check if image file exists
        if not os.path.exists(img_elem.image_path):
            # Draw placeholder if image not found
            self._render_image_placeholder(img_elem, base_x, base_y, page_height)
            return

        try:
            # Convert coordinates
            x = base_x + (img_elem.x * self.DW_TO_POINTS)
            y = page_height - self.margin - base_y - (img_elem.y * self.DW_TO_POINTS) - (img_elem.height * self.DW_TO_POINTS)
            width = img_elem.width * self.DW_TO_POINTS
            height = img_elem.height * self.DW_TO_POINTS

            # Draw image
            self.canvas.drawImage(img_elem.image_path, x, y, width, height,
                                preserveAspectRatio=True)
        except Exception as e:
            print(f"Warning: Failed to render image {img_elem.image_path}: {e}")
            self._render_image_placeholder(img_elem, base_x, base_y, page_height)

    def _render_image_placeholder(self, img_elem: ImageElement,
                                  base_x: float, base_y: float, page_height: float):
        """Render placeholder for missing image"""
        x = base_x + (img_elem.x * self.DW_TO_POINTS)
        y = page_height - self.margin - base_y - (img_elem.y * self.DW_TO_POINTS) - (img_elem.height * self.DW_TO_POINTS)
        width = img_elem.width * self.DW_TO_POINTS
        height = img_elem.height * self.DW_TO_POINTS

        # Draw rectangle
        self.canvas.setStrokeColor(colors.grey)
        self.canvas.setFillColor(colors.lightgrey)
        self.canvas.rect(x, y, width, height, stroke=1, fill=1)

        # Draw X
        self.canvas.setStrokeColor(colors.red)
        self.canvas.line(x, y, x + width, y + height)
        self.canvas.line(x + width, y, x, y + height)

    def _apply_font(self, font: FontElement):
        """Apply font definition to current state"""
        # Update font size
        if font.font_size > 0:
            self.current_font_size = font.font_size

        # Parse font style flags
        flags_str = font.font_style
        self.current_font_bold = 'PS_FONT_BOLD' in flags_str
        self.current_font_underline = 'PS_FONT_UNDERLINE' in flags_str

        # Update font name if specified
        if font.font_name:
            self.current_font_name = font.font_name
        else:
            # Default font
            self.current_font_name = "Helvetica"


class RenderOptions:
    """Options for customizing PDF rendering"""

    def __init__(self,
                 page_size=A4,
                 margin: float = 10*mm,
                 scale: float = 1.0,
                 show_grid: bool = False,
                 show_element_bounds: bool = False):
        """
        Initialize render options

        Args:
            page_size: Page size (A4, letter, etc.)
            margin: Page margin in points
            scale: Global scale factor
            show_grid: Show debug grid
            show_element_bounds: Show element bounding boxes (debug)
        """
        self.page_size = page_size
        self.margin = margin
        self.scale = scale
        self.show_grid = show_grid
        self.show_element_bounds = show_element_bounds


def render_report(template_path: str, output_path: str,
                 data_dict: Optional[dict] = None,
                 options: Optional[RenderOptions] = None):
    """
    Convenience function to render a report in one call

    Args:
        template_path: Path to .tmp template file
        output_path: Output PDF path
        data_dict: Optional dictionary for data binding {field_id: value}
        options: Optional RenderOptions

    Example:
        render_report(
            "invoice.tmp",
            "invoice.pdf",
            data_dict={1: "2024-01-15", 2: "ORD-12345"}
        )
    """
    from .parser import ReportParser
    from .data_binder import DataBinder

    # Parse template
    parser = ReportParser(template_path)
    document = parser.parse()

    # Bind data if provided
    if data_dict:
        binder = DataBinder.from_dict(data_dict)
        binder.bind(document)

    # Render to PDF
    opts = options or RenderOptions()
    renderer = PDFRenderer(page_size=opts.page_size, margin=opts.margin)
    renderer.render(document, output_path)
