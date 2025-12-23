"""
TMP to PDF Renderer using PyMuPDF

Renders parsed TmpReport to PDF, matching the layout exactly as nrp32.exe would.

Author: Claude Code
"""

import fitz  # PyMuPDF
from pathlib import Path
from typing import Optional, Tuple, List
import logging
import os

from .parser import (
    TmpReport, PageData, LayoutSection, PlankBlock,
    LabelItem, EditItem, LineItem, ImageItem, FontStyle
)

logger = logging.getLogger(__name__)


class TmpRenderer:
    """Renders TmpReport to PDF using PyMuPDF"""

    # Default page size in points (A4)
    PAGE_WIDTH = 595  # ~210mm
    PAGE_HEIGHT = 842  # ~297mm

    # Scale factor: .tmp coordinates seem to be in pixels at ~96 DPI
    # PDF uses points at 72 DPI, so scale = 72/96 = 0.75
    # But we need to calibrate based on actual output
    SCALE = 0.8  # Adjusted based on typical report width of ~732 pixels

    # Margins
    MARGIN_LEFT = 30
    MARGIN_TOP = 30

    # Font mapping
    DEFAULT_FONT = "helv"  # Helvetica
    FONT_MAP = {
        "": "helv",
        "Arial": "helv",
        "Helvetica": "helv",
        "Times": "tiro",
        "Times New Roman": "tiro",
        "Courier": "cour",
        "Courier New": "cour",
    }

    def __init__(self, report: TmpReport):
        self.report = report
        self.doc: Optional[fitz.Document] = None
        self.current_page: Optional[fitz.Page] = None
        self.page_number = 0

    def render(self, output_path: Optional[str] = None) -> bytes:
        """
        Render the report to PDF.

        Args:
            output_path: Optional path to save the PDF. If None, returns bytes only.

        Returns:
            PDF content as bytes
        """
        self.doc = fitz.open()

        # Render each page
        for page_data in self.report.pages:
            self._render_page(page_data)

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

    def _render_page(self, page_data: PageData):
        """Render a single page"""
        self.page_number = page_data.page_number
        self.current_page = self.doc.new_page(
            width=self.PAGE_WIDTH,
            height=self.PAGE_HEIGHT
        )

        # Build a text lookup from page data
        text_index = 0
        texts = page_data.raw_texts

        # Render HEAD section
        if self.report.head:
            y_offset = self.MARGIN_TOP
            text_index = self._render_section(
                self.report.head, y_offset, texts, text_index
            )

        # Render BODY section
        if self.report.body:
            y_offset = self.MARGIN_TOP + (self.report.head.height * self.SCALE if self.report.head else 0)
            text_index = self._render_section(
                self.report.body, y_offset, texts, text_index
            )

        # Render TAIL section
        if self.report.tail:
            # TAIL is usually at the bottom
            y_offset = self.PAGE_HEIGHT - (self.report.tail.height * self.SCALE) - self.MARGIN_TOP
            self._render_section(
                self.report.tail, y_offset, texts, text_index
            )

    def _render_section(self, section: LayoutSection, y_base: float,
                       texts: List[str], text_index: int) -> int:
        """Render a layout section (HEAD, BODY, or TAIL)"""
        for plank in section.planks:
            text_index = self._render_plank(plank, y_base, texts, text_index)
        return text_index

    def _render_plank(self, plank: PlankBlock, y_base: float,
                     texts: List[str], text_index: int) -> int:
        """Render a PLANK block"""
        # Skip hidden planks (size 0)
        if plank.width == 0 or plank.height == 0:
            return text_index

        # Calculate plank position
        plank_x = self.MARGIN_LEFT + (plank.x * self.SCALE)
        plank_y = y_base + (plank.y * self.SCALE)

        for item in plank.items:
            if isinstance(item, LabelItem):
                self._render_label(item, plank_x, plank_y)
            elif isinstance(item, EditItem):
                # Get text from page data
                if text_index < len(texts):
                    text = texts[text_index]
                    text_index += 1
                else:
                    text = ""
                self._render_edit(item, plank_x, plank_y, text)
            elif isinstance(item, LineItem):
                self._render_line(item, plank_x, plank_y)
            elif isinstance(item, ImageItem):
                self._render_image(item, plank_x, plank_y)

        return text_index

    def _render_label(self, label: LabelItem, plank_x: float, plank_y: float):
        """Render a static label"""
        if not label.text:
            return

        x = plank_x + (label.x * self.SCALE)
        y = plank_y + (label.y * self.SCALE)
        width = label.width * self.SCALE
        height = label.height * self.SCALE

        # Create text rectangle
        rect = fitz.Rect(x, y, x + width, y + height)

        # Get font settings
        fontname = self.DEFAULT_FONT
        fontsize = 10
        if label.font:
            fontname = self.FONT_MAP.get(label.font.name, self.DEFAULT_FONT)
            fontsize = label.font.size * 0.75  # Convert to points

        # Determine alignment
        align = fitz.TEXT_ALIGN_LEFT
        if label.alignment == "CENTER":
            align = fitz.TEXT_ALIGN_CENTER
        elif label.alignment == "RIGHT":
            align = fitz.TEXT_ALIGN_RIGHT

        try:
            self.current_page.insert_textbox(
                rect,
                label.text,
                fontname=fontname,
                fontsize=fontsize,
                align=align,
                color=(0, 0, 0)
            )
        except Exception as e:
            logger.warning(f"Failed to render label '{label.text}': {e}")

    def _render_edit(self, edit: EditItem, plank_x: float, plank_y: float, text: str):
        """Render a dynamic edit field with its value"""
        if not text:
            return

        x = plank_x + (edit.x * self.SCALE)
        y = plank_y + (edit.y * self.SCALE)
        width = edit.width * self.SCALE
        height = edit.height * self.SCALE

        # Create text rectangle
        rect = fitz.Rect(x, y, x + width, y + height)

        # Get font settings
        fontname = self.DEFAULT_FONT
        fontsize = 10
        if edit.font:
            fontname = self.FONT_MAP.get(edit.font.name, self.DEFAULT_FONT)
            fontsize = edit.font.size * 0.75

        # Determine alignment
        align = fitz.TEXT_ALIGN_LEFT
        if edit.alignment == "CENTER":
            align = fitz.TEXT_ALIGN_CENTER
        elif edit.alignment == "RIGHT":
            align = fitz.TEXT_ALIGN_RIGHT

        try:
            self.current_page.insert_textbox(
                rect,
                text,
                fontname=fontname,
                fontsize=fontsize,
                align=align,
                color=(0, 0, 0)
            )
        except Exception as e:
            logger.warning(f"Failed to render edit text '{text[:30]}': {e}")

    def _render_line(self, line: LineItem, plank_x: float, plank_y: float):
        """Render a line"""
        x1 = plank_x + (line.x * self.SCALE)
        y1 = plank_y + (line.y * self.SCALE)
        x2 = plank_x + (line.x2 * self.SCALE)
        y2 = plank_y + (line.y2 * self.SCALE)

        # Draw line
        shape = self.current_page.new_shape()
        shape.draw_line(fitz.Point(x1, y1), fitz.Point(x2, y2))
        shape.finish(color=(0, 0, 0), width=0.5)
        shape.commit()

    def _render_image(self, image: ImageItem, plank_x: float, plank_y: float):
        """Render an image"""
        x = plank_x + (image.x * self.SCALE)
        y = plank_y + (image.y * self.SCALE)
        width = image.width * self.SCALE
        height = image.height * self.SCALE

        rect = fitz.Rect(x, y, x + width, y + height)

        # Check if image file exists
        if os.path.exists(image.path):
            try:
                self.current_page.insert_image(rect, filename=image.path)
            except Exception as e:
                logger.warning(f"Failed to insert image '{image.path}': {e}")
                # Draw placeholder rectangle
                self._draw_placeholder(rect, "IMAGE")
        else:
            # Try to find the image in backup folder
            backup_path = Path(__file__).parent.parent.parent / "nrp_backup" / "report_images"
            image_name = Path(image.path).name
            alt_path = backup_path / image_name

            if alt_path.exists():
                try:
                    self.current_page.insert_image(rect, filename=str(alt_path))
                except Exception as e:
                    logger.warning(f"Failed to insert backup image: {e}")
                    self._draw_placeholder(rect, "IMAGE")
            else:
                self._draw_placeholder(rect, "IMAGE")

    def _draw_placeholder(self, rect: fitz.Rect, text: str = ""):
        """Draw a placeholder rectangle for missing images"""
        shape = self.current_page.new_shape()
        shape.draw_rect(rect)
        shape.finish(color=(0.8, 0.8, 0.8), fill=(0.95, 0.95, 0.95), width=0.5)
        shape.commit()

        if text:
            self.current_page.insert_textbox(
                rect,
                text,
                fontsize=8,
                align=fitz.TEXT_ALIGN_CENTER,
                color=(0.5, 0.5, 0.5)
            )


def render_tmp_to_pdf(tmp_path: str, output_path: Optional[str] = None) -> bytes:
    """
    Convenience function to render a .tmp file to PDF.

    Args:
        tmp_path: Path to the .tmp file
        output_path: Optional path to save the PDF

    Returns:
        PDF content as bytes
    """
    from .parser import parse_tmp_file

    report = parse_tmp_file(tmp_path)
    renderer = TmpRenderer(report)
    return renderer.render(output_path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python renderer.py <file.tmp> [output.pdf]")
        sys.exit(1)

    tmp_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output.pdf"

    print(f"Rendering {tmp_path} -> {output_path}")
    pdf_bytes = render_tmp_to_pdf(tmp_path, output_path)
    print(f"Generated {len(pdf_bytes)} bytes")
