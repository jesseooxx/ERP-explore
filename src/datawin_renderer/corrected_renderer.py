"""
修正版渲染器 - 正確的座標轉換和分頁邏輯
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
import os
from typing import List

from .parser import (
    ReportDocument, ReportElement, PlankElement, LabelElement,
    EditElement, LineElement, ImageElement, FontElement, HeadElement, PSFlags
)


class CorrectedPDFRenderer:
    """
    修正後的PDF渲染器

    關鍵修正:
    1. 座標轉換: 模板單位直接對應 PDF points (縮放至頁面尺寸)
    2. 多頁渲染: 支持分頁邏輯
    3. 正確的 Y 軸反轉
    """

    def __init__(self, page_size=A4, margin: float = 10*mm):
        self.page_size = page_size
        self.margin = margin
        self.canvas = None

        # 頁面尺寸
        self.page_width, self.page_height = page_size

        # 座標縮放因子
        # 模板聲稱: 900 x 1200
        # A4 實際: 595 x 842 points
        self.scale_x = self.page_width / 900
        self.scale_y = self.page_height / 1200

        # 當前字體狀態
        self.current_font_name = "Helvetica"
        self.current_font_size = 12
        self.current_font_bold = False
        self.current_font_underline = False

    def render(self, document: ReportDocument, output_path: str):
        """渲染文檔到 PDF"""
        # 創建 canvas
        self.canvas = canvas.Canvas(output_path, pagesize=self.page_size)

        # 設置元數據
        if document.title:
            self.canvas.setTitle(document.title)
        self.canvas.setAuthor("Datawin Renderer (Corrected)")

        # 檢測頁面
        pages = self._detect_pages(document)

        print(f"檢測到 {len(pages)} 個頁面")

        # 渲染每一頁
        for page_idx, planks in enumerate(pages):
            print(f"  渲染頁 {page_idx + 1}: {len(planks)} 個 PLANK")
            self._render_page(document, planks, page_idx)
            self.canvas.showPage()

        # 保存
        self.canvas.save()
        print(f"PDF 已保存: {output_path}")

    def _detect_pages(self, document: ReportDocument) -> List[List[PlankElement]]:
        """
        檢測頁面邊界

        規則:
        1. 圖片 PLANK (ID >= 999) 可能單獨成頁
        2. 根據 Y 座標分組
        3. 根據內容類型分組
        """
        all_planks = document.get_planks()

        # 分類 PLANK
        normal_planks = []
        image_planks = []

        for plank in all_planks:
            # 檢查是否包含圖片
            has_image = any(isinstance(child, ImageElement) for child in plank.children)

            if plank.id_num >= 999 or has_image:
                image_planks.append(plank)
            else:
                normal_planks.append(plank)

        pages = []

        # 頁面 1: 主要內容
        if normal_planks:
            pages.append(normal_planks)

        # 圖片頁面 (可能需要分割)
        # 簡單策略: 每 2 個圖片 PLANK 一頁
        for i in range(0, len(image_planks), 2):
            page_planks = image_planks[i:i+2]
            pages.append(page_planks)

        return pages

    def _render_page(self, document: ReportDocument, planks: List[PlankElement], page_num: int):
        """渲染單個頁面"""

        # 渲染 HEAD (如果是第一頁)
        if page_num == 0:
            head = document.get_head()
            if head:
                self._render_head(head)

        # 渲染 PLANK
        for plank in planks:
            self._render_plank(plank)

    def _render_head(self, head: HeadElement):
        """渲染頁面頭部"""
        if not head:
            return

        flags = head.get_style_flag_value()

        # 頭部高度（縮放）
        head_height = head.head_size * self.scale_y
        x = self.margin
        y = self.page_height - self.margin - head_height
        width = self.page_width - 2 * self.margin

        # 繪製邊框
        if flags & PSFlags.PS_BORDER:
            self.canvas.setStrokeColor(colors.black)
            self.canvas.setLineWidth(1)
            self.canvas.rect(x, y, width, head_height, stroke=1, fill=0)

        # 繪製陰影
        if flags & PSFlags.PS_SHADOW:
            shadow_offset = 3
            self.canvas.setStrokeColor(colors.gray)
            self.canvas.setFillColor(colors.lightgrey)
            self.canvas.rect(x + shadow_offset, y - shadow_offset,
                           width, head_height, stroke=1, fill=1)

    def _render_plank(self, plank: PlankElement):
        """渲染 PLANK 容器及其子元素"""

        # 轉換 PLANK 座標（修正版）
        plank_x = self.margin + (plank.x * self.scale_x)
        plank_y = plank.y * self.scale_y  # 相對 Y，稍後轉換

        # 渲染子元素
        for child in plank.children:
            self._render_element(child, plank_x, plank_y)

    def _render_element(self, elem: ReportElement, base_x: float, base_y: float):
        """渲染單個元素"""

        if isinstance(elem, LabelElement):
            self._render_label(elem, base_x, base_y)
        elif isinstance(elem, EditElement):
            self._render_edit(elem, base_x, base_y)
        elif isinstance(elem, LineElement):
            self._render_line(elem, base_x, base_y)
        elif isinstance(elem, ImageElement):
            self._render_image(elem, base_x, base_y)

    def _render_label(self, label: LabelElement, base_x: float, base_y: float):
        """渲染靜態文本"""
        self._render_text(label.text, label, base_x, base_y)

    def _render_edit(self, edit: EditElement, base_x: float, base_y: float):
        """渲染 EDIT 字段"""
        text = edit.bound_data if edit.bound_data else f"[EDIT_{edit.id_num}]"
        self._render_text(text, edit, base_x, base_y)

    def _render_text(self, text: str, elem: ReportElement,
                    base_x: float, base_y: float):
        """
        渲染文本（修正版座標）
        """
        if not text:
            return

        # 轉換座標（修正版）
        x = base_x + (elem.x * self.scale_x)

        # Y 軸反轉（PDF 原點在左下，模板原點在左上）
        # y_template = base_y + elem.y (向下增加)
        # y_pdf = page_height - y_template (轉換為向上增加)
        y_from_top = base_y + elem.y * self.scale_y
        y = self.page_height - self.margin - y_from_top - (elem.height * self.scale_y)

        # 設置字體
        font_name = self.current_font_name
        font_size = self.current_font_size

        if self.current_font_bold:
            if "Helvetica" in font_name:
                font_name = "Helvetica-Bold"
            elif "Times" in font_name:
                font_name = "Times-Bold"

        self.canvas.setFont(font_name, font_size)

        # 計算對齊
        text_width = self.canvas.stringWidth(text, font_name, font_size)
        elem_width = elem.width * self.scale_x

        flags = elem.get_style_flag_value()
        x_offset = 0
        if flags & PSFlags.PS_CENTER:
            x_offset = (elem_width - text_width) / 2
        elif flags & PSFlags.PS_RIGHT:
            x_offset = elem_width - text_width

        # 繪製文本
        self.canvas.drawString(x + x_offset, y, text)

        # 下劃線
        if self.current_font_underline:
            underline_y = y - 2
            self.canvas.line(x + x_offset, underline_y,
                           x + x_offset + text_width, underline_y)

    def _render_line(self, line: LineElement, base_x: float, base_y: float):
        """渲染線條"""

        # 轉換座標
        x1 = base_x + (line.x * self.scale_x)
        y1_from_top = base_y + line.y * self.scale_y
        y1 = self.page_height - self.margin - y1_from_top

        x2 = base_x + (line.x2 * self.scale_x)
        y2_from_top = base_y + line.y2 * self.scale_y
        y2 = self.page_height - self.margin - y2_from_top

        # 設置線條樣式
        self.canvas.setLineWidth(line.thickness * 0.5)
        self.canvas.setStrokeColor(colors.black)

        # 繪製線條
        self.canvas.line(x1, y1, x2, y2)

    def _render_image(self, img_elem: ImageElement, base_x: float, base_y: float):
        """渲染圖片"""

        if not os.path.exists(img_elem.image_path):
            # 繪製佔位符
            x = base_x + (img_elem.x * self.scale_x)
            y_from_top = base_y + img_elem.y * self.scale_y
            y = self.page_height - self.margin - y_from_top - (img_elem.height * self.scale_y)

            width = img_elem.width * self.scale_x
            height = img_elem.height * self.scale_y

            # 佔位符矩形
            self.canvas.setStrokeColor(colors.grey)
            self.canvas.setFillColor(colors.lightgrey)
            self.canvas.rect(x, y, width, height, stroke=1, fill=1)

            # X 標記
            self.canvas.setStrokeColor(colors.red)
            self.canvas.line(x, y, x + width, y + height)
            self.canvas.line(x + width, y, x, y + height)
            return

        try:
            x = base_x + (img_elem.x * self.scale_x)
            y_from_top = base_y + img_elem.y * self.scale_y
            y = self.page_height - self.margin - y_from_top - (img_elem.height * self.scale_y)

            width = img_elem.width * self.scale_x
            height = img_elem.height * self.scale_y

            self.canvas.drawImage(img_elem.image_path, x, y, width, height,
                                preserveAspectRatio=True)
        except Exception as e:
            print(f"警告: 無法渲染圖片 {img_elem.image_path}: {e}")
