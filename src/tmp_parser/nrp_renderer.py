"""
NRP32-Compatible PDF Renderer

Renders .tmp files to PDF following the exact nrp32.exe architecture:
1. Parse layout definition (HEAD/BODY/TAIL sections with PLANK containers)
2. For each page, iterate through PLANKs and render elements
3. LABEL: draw static text
4. EDIT: fill with data from raw_texts (in order)
5. LINE: draw lines
6. IMAGE: draw images

This is a faithful reimplementation of nrp32's rendering model for fast PDF generation.

Author: Claude Code
"""

import fitz
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import logging
import os

from .parser import (
    TmpReport, PageData, LayoutSection, PlankBlock,
    LabelItem, EditItem, LineItem, ImageItem, FontStyle,
    parse_tmp_file
)

logger = logging.getLogger(__name__)


class NrpRenderer:
    """
    Renders TmpReport to PDF using nrp32's original architecture.

    Key concepts:
    - Coordinate unit in .tmp: approximately 0.1mm or twips
    - Scale factor to convert to PDF points (72 DPI)
    - PLANK containers provide absolute positioning
    - Elements within PLANK use relative coordinates
    """

    # Page dimensions (from .tmp: typically 900 units wide)
    # Scale: 900 units -> ~595 points (A4 width)
    SCALE = 595.0 / 900.0  # ~0.66

    # Page size in points (A4)
    PAGE_WIDTH = 595.0
    PAGE_HEIGHT = 842.0

    # Margins
    MARGIN_LEFT = 20
    MARGIN_TOP = 10

    # Font settings
    DEFAULT_FONT = "helv"
    FONT_BOLD = "hebo"

    def __init__(self, report: TmpReport):
        self.report = report
        self.doc: Optional[fitz.Document] = None
        self.current_page: Optional[fitz.Page] = None
        self.page_number = 0
        self.edit_index = 0  # Index into raw_texts for EDIT values

        # Image search paths
        self.image_paths = [
            Path(__file__).parent.parent.parent / "nrp_backup" / "report_images",
            Path("X:/LEILA/NRP32"),
            Path("Z:/LEILA/NRP32"),
            Path(os.environ.get('TEMP', '/tmp')),
        ]

    def render(self, output_path: Optional[str] = None) -> bytes:
        """Render the report to PDF"""
        self.doc = fitz.open()

        # Render each page
        for page_data in self.report.pages:
            self._render_page(page_data)

        # Get PDF bytes
        pdf_bytes = self.doc.tobytes()

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self.doc.save(str(output_path))
            logger.info(f"Saved PDF to {output_path}")

        self.doc.close()
        return pdf_bytes

    def _render_page(self, page_data: PageData):
        """Render a single page following nrp32 model"""
        self.page_number = page_data.page_number
        self.current_page = self.doc.new_page(
            width=self.PAGE_WIDTH,
            height=self.PAGE_HEIGHT
        )

        # Reset EDIT index for this page
        self.edit_index = 0
        texts = page_data.raw_texts

        # Determine page type for selecting appropriate PLANKs
        is_first = (page_data.page_number == 1)
        is_last = (page_data.page_number == self.report.page_count)

        # Render HEAD section (header)
        if self.report.head:
            self._render_section(self.report.head, 0, texts, is_first)

        # Render BODY section (content/table)
        if self.report.body:
            head_height = self.report.head.height * self.SCALE if self.report.head else 0
            self._render_section(self.report.body, head_height, texts, is_first)

        # Render TAIL section (footer)
        if self.report.tail:
            tail_y = self.PAGE_HEIGHT - (self.report.tail.height * self.SCALE) - self.MARGIN_TOP
            self._render_section(self.report.tail, tail_y, texts, is_first)

    def _render_section(self, section: LayoutSection, y_offset: float,
                       texts: List[str], is_first_page: bool):
        """Render a layout section (HEAD, BODY, or TAIL)"""
        # Group PLANKs by position to find which ones to render
        # nrp32 has multiple PLANKs at same position for different report types
        # We'll render the first matching PLANK at each position

        rendered_positions = set()

        for plank in section.planks:
            # Skip PLANKs with zero size (hidden)
            if plank.width <= 0 or plank.height <= 0:
                continue

            # Calculate absolute position
            abs_x = self.MARGIN_LEFT + (plank.x * self.SCALE)
            abs_y = self.MARGIN_TOP + y_offset + (plank.y * self.SCALE)

            # Create position key (round to avoid float comparison issues)
            pos_key = (round(abs_x), round(abs_y))

            # Skip if we already rendered a PLANK at this position
            # (This handles alternative templates)
            if pos_key in rendered_positions:
                continue

            # Render the PLANK
            self._render_plank(plank, abs_x, abs_y, texts)
            rendered_positions.add(pos_key)

    def _render_plank(self, plank: PlankBlock, abs_x: float, abs_y: float,
                     texts: List[str]):
        """Render a single PLANK and its contents"""
        for item in plank.items:
            if isinstance(item, LabelItem):
                self._render_label(item, abs_x, abs_y)
            elif isinstance(item, EditItem):
                # Get text from raw_texts
                if self.edit_index < len(texts):
                    text = texts[self.edit_index]
                    self.edit_index += 1
                else:
                    text = ""
                self._render_edit(item, abs_x, abs_y, text)
            elif isinstance(item, LineItem):
                self._render_line(item, abs_x, abs_y)
            elif isinstance(item, ImageItem):
                self._render_image(item, abs_x, abs_y)

    def _render_label(self, label: LabelItem, base_x: float, base_y: float):
        """Render a static LABEL element"""
        if not label.text:
            return

        x = base_x + (label.x * self.SCALE)
        y = base_y + (label.y * self.SCALE)

        # Get font settings
        fontname = self.DEFAULT_FONT
        fontsize = 10
        if label.font:
            fontsize = label.font.size * 0.75  # Convert to points
            if label.font.bold:
                fontname = self.FONT_BOLD

        self._draw_text(label.text, x, y, fontname, fontsize, label.alignment)

    def _render_edit(self, edit: EditItem, base_x: float, base_y: float, text: str):
        """Render an EDIT element with its value"""
        if not text:
            return

        x = base_x + (edit.x * self.SCALE)
        y = base_y + (edit.y * self.SCALE)

        # Get font settings
        fontname = self.DEFAULT_FONT
        fontsize = 10
        if edit.font:
            fontsize = edit.font.size * 0.75
            if edit.font.bold:
                fontname = self.FONT_BOLD

        self._draw_text(text, x, y, fontname, fontsize, edit.alignment)

    def _render_line(self, line: LineItem, base_x: float, base_y: float):
        """Render a LINE element"""
        x1 = base_x + (line.x * self.SCALE)
        y1 = base_y + (line.y * self.SCALE)
        x2 = base_x + (line.x2 * self.SCALE)
        y2 = base_y + (line.y2 * self.SCALE)

        shape = self.current_page.new_shape()
        shape.draw_line(fitz.Point(x1, y1), fitz.Point(x2, y2))
        shape.finish(color=(0, 0, 0), width=0.5)
        shape.commit()

    def _render_image(self, image: ImageItem, base_x: float, base_y: float):
        """Render an IMAGE element"""
        x = base_x + (image.x * self.SCALE)
        y = base_y + (image.y * self.SCALE)
        width = image.width * self.SCALE
        height = image.height * self.SCALE

        rect = fitz.Rect(x, y, x + width, y + height)

        # Find the image file
        image_path = self._find_image(image.path)
        if image_path:
            try:
                self.current_page.insert_image(rect, filename=str(image_path))
            except Exception as e:
                logger.warning(f"Failed to insert image: {e}")
                self._draw_placeholder(rect)
        else:
            self._draw_placeholder(rect)

    def _draw_text(self, text: str, x: float, y: float,
                   fontname: str, fontsize: float, alignment: str):
        """Draw text with specified alignment"""
        if not text:
            return

        try:
            # PyMuPDF insert_text uses baseline position
            baseline_y = y + fontsize

            self.current_page.insert_text(
                (x, baseline_y),
                text,
                fontname=fontname,
                fontsize=fontsize,
                color=(0, 0, 0)
            )
        except Exception as e:
            logger.warning(f"Failed to draw text '{text[:20]}': {e}")

    def _draw_placeholder(self, rect: fitz.Rect):
        """Draw a placeholder for missing images"""
        shape = self.current_page.new_shape()
        shape.draw_rect(rect)
        shape.finish(color=(0.8, 0.8, 0.8), fill=(0.95, 0.95, 0.95), width=0.5)
        shape.commit()

    def _find_image(self, original_path: str) -> Optional[Path]:
        """Find image file from various possible locations"""
        # Extract filename from path
        filename = Path(original_path).name

        # Search in configured paths
        for search_path in self.image_paths:
            if not search_path.exists():
                continue

            # Try exact filename
            full_path = search_path / filename
            if full_path.exists():
                return full_path

            # Try case-insensitive search
            for f in search_path.iterdir():
                if f.name.lower() == filename.lower():
                    return f

        # Try original path as fallback
        if Path(original_path).exists():
            return Path(original_path)

        return None


def render_nrp_to_pdf(tmp_path: str, output_path: Optional[str] = None) -> bytes:
    """
    Render a .tmp file to PDF using nrp32-compatible renderer.

    Args:
        tmp_path: Path to the .tmp file
        output_path: Optional path to save the PDF

    Returns:
        PDF content as bytes
    """
    report = parse_tmp_file(tmp_path)
    renderer = NrpRenderer(report)
    return renderer.render(output_path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nrp_renderer.py <file.tmp> [output.pdf]")
        sys.exit(1)

    tmp_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output_nrp.pdf"

    print(f"Rendering {tmp_path} -> {output_path}")
    pdf_bytes = render_nrp_to_pdf(tmp_path, output_path)
    print(f"Generated {len(pdf_bytes):,} bytes")
