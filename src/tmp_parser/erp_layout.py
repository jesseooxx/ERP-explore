"""
ERP PDF Layout Analyzer and Template Extractor

Extracts the exact layout from ERP-generated PDFs to use as a template
for generating new PDFs with the same look.

Author: Claude Code
"""

import fitz
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class TextElement:
    """A text element extracted from PDF"""
    text: str
    x: float
    y: float
    width: float
    height: float
    font_name: str = ""
    font_size: float = 10
    is_bold: bool = False
    is_italic: bool = False
    color: Tuple[float, float, float] = (0, 0, 0)

    # Field type for template matching
    field_type: str = "static"  # "static", "dynamic", "label"


@dataclass
class LineElement:
    """A line element"""
    x1: float
    y1: float
    x2: float
    y2: float
    width: float = 0.5
    color: Tuple[float, float, float] = (0, 0, 0)


@dataclass
class ImageElement:
    """An image element"""
    x: float
    y: float
    width: float
    height: float
    image_data: Optional[bytes] = None


@dataclass
class PageTemplate:
    """Template for a page type"""
    page_type: str  # "first", "middle", "last", "single"
    width: float
    height: float
    header_image: Optional[ImageElement] = None
    text_elements: List[TextElement] = field(default_factory=list)
    line_elements: List[LineElement] = field(default_factory=list)

    # Field mappings: position -> data field name
    field_mappings: Dict[str, str] = field(default_factory=dict)


class ERPLayoutAnalyzer:
    """Analyzes ERP-generated PDFs to extract layout templates"""

    def __init__(self):
        self.templates: Dict[str, PageTemplate] = {}

    def analyze_pdf(self, pdf_path: str) -> Dict[str, PageTemplate]:
        """Analyze a PDF and extract page templates"""
        doc = fitz.open(pdf_path)

        for page_idx, page in enumerate(doc):
            page_type = self._determine_page_type(page_idx, len(doc))
            template = self._extract_page_template(page, page_type)
            self.templates[page_type] = template

        doc.close()
        return self.templates

    def _determine_page_type(self, page_idx: int, total_pages: int) -> str:
        """Determine the type of page for templating"""
        if total_pages == 1:
            return "single"
        elif page_idx == 0:
            return "first"
        elif page_idx == total_pages - 1:
            return "last"
        else:
            return "middle"

    def _extract_page_template(self, page: fitz.Page, page_type: str) -> PageTemplate:
        """Extract template from a page"""
        template = PageTemplate(
            page_type=page_type,
            width=page.rect.width,
            height=page.rect.height
        )

        # Extract text elements
        blocks = page.get_text("dict")["blocks"]

        for block in blocks:
            if block.get("type") == 0:  # Text block
                self._extract_text_elements(block, template)
            elif block.get("type") == 1:  # Image block
                self._extract_image_element(block, template)

        # Extract line drawings
        drawings = page.get_drawings()
        for d in drawings:
            if d.get("type") == "l":  # Line
                template.line_elements.append(LineElement(
                    x1=d["rect"][0],
                    y1=d["rect"][1],
                    x2=d["rect"][2],
                    y2=d["rect"][3]
                ))

        # Identify dynamic fields (fields that change per document)
        self._identify_dynamic_fields(template)

        return template

    def _extract_text_elements(self, block: dict, template: PageTemplate):
        """Extract text elements from a text block"""
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                text = span.get("text", "").strip()
                if not text:
                    continue

                bbox = span.get("bbox", [0, 0, 0, 0])
                font = span.get("font", "")
                size = span.get("size", 10)
                flags = span.get("flags", 0)
                color = span.get("color", 0)

                # Parse color (int to RGB tuple)
                if isinstance(color, int):
                    r = ((color >> 16) & 255) / 255
                    g = ((color >> 8) & 255) / 255
                    b = (color & 255) / 255
                    color_tuple = (r, g, b)
                else:
                    color_tuple = (0, 0, 0)

                elem = TextElement(
                    text=text,
                    x=bbox[0],
                    y=bbox[1],
                    width=bbox[2] - bbox[0],
                    height=bbox[3] - bbox[1],
                    font_name=font,
                    font_size=size,
                    is_bold=bool(flags & 16),  # Bold flag
                    is_italic=bool(flags & 2),  # Italic flag
                    color=color_tuple
                )
                template.text_elements.append(elem)

    def _extract_image_element(self, block: dict, template: PageTemplate):
        """Extract image element (usually header image)"""
        bbox = block.get("bbox", [0, 0, 0, 0])

        # Check if this is the header image (at top of page)
        if bbox[1] < 150:  # Near top
            template.header_image = ImageElement(
                x=bbox[0],
                y=bbox[1],
                width=bbox[2] - bbox[0],
                height=bbox[3] - bbox[1]
            )

    def _identify_dynamic_fields(self, template: PageTemplate):
        """Identify which text elements are dynamic (change per document)"""
        # Known static labels
        static_labels = {
            "PROFORMA INVOICE", "PAGE :", "Date :", "ORDER:", "Ref. :",
            "Cust#:", "Tel #:", "Fax #:", "Messrs. :", "Payment :",
            "Shipment:", "Seq.", "Item No./Cust_Item", "Description",
            "Quantity", "Unit Price", "Amount", "Total:", "SAY TOTAL",
            "Confirmed By", "Your faithfully", "The Authorized",
            "Shipping Mark", "Side Mark", "Total Page:"
        }

        for elem in template.text_elements:
            # Check if it's a known static label
            if any(label in elem.text for label in static_labels):
                elem.field_type = "label"
            else:
                # Assume dynamic
                elem.field_type = "dynamic"

    def save_templates(self, output_path: str):
        """Save templates to JSON file"""
        data = {}
        for page_type, template in self.templates.items():
            data[page_type] = {
                "page_type": template.page_type,
                "width": template.width,
                "height": template.height,
                "text_elements": [
                    {
                        "text": e.text,
                        "x": e.x, "y": e.y,
                        "width": e.width, "height": e.height,
                        "font_name": e.font_name,
                        "font_size": e.font_size,
                        "is_bold": e.is_bold,
                        "field_type": e.field_type
                    }
                    for e in template.text_elements
                ],
                "line_elements": [
                    {"x1": l.x1, "y1": l.y1, "x2": l.x2, "y2": l.y2}
                    for l in template.line_elements
                ]
            }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved templates to {output_path}")


def extract_erp_layout(pdf_path: str, output_path: Optional[str] = None) -> Dict[str, PageTemplate]:
    """
    Convenience function to extract layout from ERP PDF.

    Args:
        pdf_path: Path to ERP-generated PDF
        output_path: Optional path to save templates as JSON

    Returns:
        Dictionary of page templates
    """
    analyzer = ERPLayoutAnalyzer()
    templates = analyzer.analyze_pdf(pdf_path)

    if output_path:
        analyzer.save_templates(output_path)

    return templates


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python erp_layout.py <erp_sample.pdf> [output.json]")
        sys.exit(1)

    pdf_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "erp_layout.json"

    templates = extract_erp_layout(pdf_path, output_path)

    print(f"\nExtracted {len(templates)} page templates:")
    for page_type, template in templates.items():
        print(f"\n  {page_type}:")
        print(f"    Size: {template.width:.1f} x {template.height:.1f}")
        print(f"    Text elements: {len(template.text_elements)}")
        print(f"    Line elements: {len(template.line_elements)}")

        # Count dynamic fields
        dynamic = [e for e in template.text_elements if e.field_type == "dynamic"]
        print(f"    Dynamic fields: {len(dynamic)}")
