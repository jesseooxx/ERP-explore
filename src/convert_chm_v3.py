# -*- coding: utf-8 -*-
"""
CHM 轉 PDF 轉換器 v3
- 可點擊跳轉的目錄 (書籤 + 內部連結)
- 支援圖片嵌入
- 改進排版
"""

import os
import re
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Image, Flowable
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor, blue
from PIL import Image as PILImage

# 頁面設定
PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 2 * cm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

# 全域字體
FONT_NAME = 'Helvetica'

def init_font():
    """初始化中文字體"""
    global FONT_NAME
    font_paths = [
        (r"C:\Windows\Fonts\msjh.ttc", 0),
        (r"C:\Windows\Fonts\mingliu.ttc", 0),
    ]
    for path, idx in font_paths:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont('Chinese', path, subfontIndex=idx))
                FONT_NAME = 'Chinese'
                print(f"字體載入: {path}")
                return
            except:
                pass

def read_big5(path):
    """讀取 Big5 編碼檔案"""
    for enc in ['big5', 'cp950', 'utf-8']:
        try:
            with open(path, 'rb') as f:
                return f.read().decode(enc, errors='replace')
        except:
            pass
    return ""

def strip_html(html):
    """移除 HTML 標籤，保留結構"""
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<br\s*/?>', '\n', html, flags=re.I)
    html = re.sub(r'</p>', '\n\n', html, flags=re.I)
    html = re.sub(r'</div>', '\n', html, flags=re.I)
    html = re.sub(r'</tr>', '\n', html, flags=re.I)
    html = re.sub(r'</h[1-6]>', '\n\n', html, flags=re.I)
    html = re.sub(r'<[^>]+>', '', html)
    html = html.replace('&nbsp;', ' ').replace('&amp;', '&')
    html = html.replace('&lt;', '<').replace('&gt;', '>')
    html = re.sub(r'[ \t]+', ' ', html)
    html = re.sub(r'\n{3,}', '\n\n', html)
    return html.strip()

def safe_text(text):
    """清理文字供 PDF 使用"""
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(text))
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def get_img_refs(html):
    """從 HTML 提取圖片參考"""
    return re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I)

def parse_html_sequential(html):
    """
    按順序解析 HTML，保持文字和圖片的原始排列
    回傳: [{'type': 'text', 'content': '...'}, {'type': 'image', 'src': '...'}, ...]
    """
    # 移除 script 和 style
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<head[^>]*>.*?</head>', '', html, flags=re.DOTALL|re.I)

    elements = []

    # 用特殊標記替換圖片，以便後續分割
    img_placeholder = "___IMG_PLACEHOLDER_{}_PLACEHOLDER___"
    img_sources = []

    def replace_img(match):
        src_match = re.search(r'src=["\']([^"\']+)["\']', match.group(0), re.I)
        if src_match:
            idx = len(img_sources)
            img_sources.append(src_match.group(1))
            return img_placeholder.format(idx)
        return ''

    html = re.sub(r'<img[^>]*>', replace_img, html, flags=re.I)

    # 處理換行標籤
    html = re.sub(r'<br\s*/?>', '\n', html, flags=re.I)
    html = re.sub(r'</p>', '\n\n', html, flags=re.I)
    html = re.sub(r'</div>', '\n', html, flags=re.I)
    html = re.sub(r'</tr>', '\n', html, flags=re.I)
    html = re.sub(r'</td>', ' ', html, flags=re.I)
    html = re.sub(r'</h[1-6]>', '\n\n', html, flags=re.I)
    html = re.sub(r'</li>', '\n', html, flags=re.I)

    # 移除剩餘標籤
    html = re.sub(r'<[^>]+>', '', html)

    # 處理 HTML 實體
    html = html.replace('&nbsp;', ' ').replace('&amp;', '&')
    html = html.replace('&lt;', '<').replace('&gt;', '>')
    html = html.replace('&quot;', '"')

    # 按圖片標記分割，保持順序
    parts = re.split(r'(___IMG_PLACEHOLDER_\d+_PLACEHOLDER___)', html)

    for part in parts:
        # 檢查是否為圖片標記
        img_match = re.match(r'___IMG_PLACEHOLDER_(\d+)_PLACEHOLDER___', part)
        if img_match:
            idx = int(img_match.group(1))
            if idx < len(img_sources):
                elements.append({'type': 'image', 'src': img_sources[idx]})
        else:
            # 處理文字部分
            text = re.sub(r'[ \t]+', ' ', part)
            text = re.sub(r'\n{3,}', '\n\n', text)

            # 分段
            for para in text.split('\n\n'):
                para = para.strip()
                if para and len(para) > 1:
                    elements.append({'type': 'text', 'content': para})

    return elements

def get_chapters(hhc_path):
    """從 HHC 取得章節"""
    content = read_big5(hhc_path)
    pattern = r'<param\s+name="Name"\s+value="([^"]+)".*?<param\s+name="Local"\s+value="([^"]+)"'
    return [{'name': m[0], 'file': m[1]} for m in re.findall(pattern, content, re.I|re.DOTALL)]

def make_anchor_name(index):
    """建立錨點名稱"""
    return f"chapter_{index}"

class BookmarkParagraph(Paragraph):
    """帶書籤的段落"""
    def __init__(self, text, style, bookmark_name=None, bookmark_text=None):
        Paragraph.__init__(self, text, style)
        self.bookmark_name = bookmark_name
        self.bookmark_text = bookmark_text

    def draw(self):
        if self.bookmark_name:
            self.canv.bookmarkPage(self.bookmark_name)
            if self.bookmark_text:
                self.canv.addOutlineEntry(self.bookmark_text, self.bookmark_name, level=0)
        Paragraph.draw(self)

class LinkedParagraph(Paragraph):
    """帶內部連結的段落"""
    def __init__(self, text, style, link_name=None):
        # 如果有連結，用特殊格式
        if link_name:
            text = f'<a href="#{link_name}" color="blue">{text}</a>'
        Paragraph.__init__(self, text, style)

def create_styles():
    """建立樣式"""
    return {
        'title': ParagraphStyle(
            'Title',
            fontName=FONT_NAME,
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=HexColor('#003366')
        ),
        'subtitle': ParagraphStyle(
            'Subtitle',
            fontName=FONT_NAME,
            fontSize=12,
            alignment=TA_CENTER,
            spaceAfter=10,
            textColor=HexColor('#666666')
        ),
        'toc_title': ParagraphStyle(
            'TOCTitle',
            fontName=FONT_NAME,
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=HexColor('#003366')
        ),
        'toc_item': ParagraphStyle(
            'TOCItem',
            fontName=FONT_NAME,
            fontSize=11,
            leading=20,
            spaceBefore=2,
            spaceAfter=2,
            leftIndent=10,
            textColor=HexColor('#0066CC')  # 藍色連結樣式
        ),
        'chapter': ParagraphStyle(
            'Chapter',
            fontName=FONT_NAME,
            fontSize=16,
            spaceBefore=25,
            spaceAfter=15,
            textColor=HexColor('#0055AA'),
            borderWidth=0,
            borderPadding=5,
            backColor=HexColor('#F0F5FF')
        ),
        'body': ParagraphStyle(
            'Body',
            fontName=FONT_NAME,
            fontSize=10,
            leading=16,
            spaceBefore=6,
            spaceAfter=6,
        ),
    }

def convert_chm_to_pdf(extract_dir, output_pdf, title_zh, title_en):
    """轉換 CHM 為 PDF（帶可點擊目錄）"""

    print(f"\n{'='*50}")
    print(f"處理: {title_zh}")
    print(f"{'='*50}")

    # 找 HHC
    hhc_files = list(Path(extract_dir).glob("*.hhc"))
    if not hhc_files:
        print(f"  錯誤: 找不到 HHC")
        return False

    chapters = get_chapters(str(hhc_files[0]))
    if not chapters:
        htm_files = sorted(Path(extract_dir).glob("*.htm"))
        chapters = [{'name': f.stem, 'file': f.name} for f in htm_files]

    print(f"  章節數: {len(chapters)}")

    # 建立 PDF
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=A4,
        rightMargin=MARGIN,
        leftMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN
    )

    styles = create_styles()
    story = []

    # === 封面 ===
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph(safe_text(title_zh), styles['title']))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(safe_text(title_en), styles['subtitle']))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(safe_text("DataWin ERP 系統說明文件"), styles['subtitle']))
    story.append(PageBreak())

    # === 可點擊目錄 ===
    story.append(Paragraph(safe_text("目 錄"), styles['toc_title']))
    story.append(Paragraph(safe_text("（點擊章節名稱可跳轉）"), styles['subtitle']))
    story.append(Spacer(1, 0.5*cm))

    for i, ch in enumerate(chapters, 1):
        anchor_name = make_anchor_name(i)
        # 建立可點擊的目錄項目
        toc_text = f'{i}. {safe_text(ch["name"])}'
        link_para = Paragraph(
            f'<a href="#{anchor_name}" color="#0066CC">{toc_text}</a>',
            styles['toc_item']
        )
        story.append(link_para)

    story.append(PageBreak())

    # === 內容（帶書籤錨點）===
    img_count = 0

    for i, ch in enumerate(chapters, 1):
        anchor_name = make_anchor_name(i)
        ch_name = ch['name']

        # 每個章節從新頁面開始
        story.append(PageBreak())

        # 章節標題帶書籤（可從側邊欄跳轉 + 目錄連結目標）
        chapter_para = BookmarkParagraph(
            safe_text(ch_name),
            styles['chapter'],
            bookmark_name=anchor_name,
            bookmark_text=f"{i}. {ch_name}"
        )
        story.append(chapter_para)

        # 讀取 HTML 內容，按原始順序處理
        htm_path = os.path.join(extract_dir, ch['file'])
        if os.path.exists(htm_path):
            html = read_big5(htm_path)

            # 按順序解析 HTML（文字和圖片交錯）
            elements = parse_html_sequential(html)

            for elem in elements:
                if elem['type'] == 'image':
                    img_path = os.path.join(extract_dir, elem['src'].replace('/', os.sep))
                    if os.path.exists(img_path):
                        try:
                            with PILImage.open(img_path) as pil_img:
                                w, h = pil_img.size
                            max_w = CONTENT_WIDTH
                            max_h = 12 * cm
                            scale = min(max_w / w, max_h / h, 1)
                            story.append(Spacer(1, 0.2*cm))
                            story.append(Image(img_path, width=w*scale, height=h*scale))
                            story.append(Spacer(1, 0.3*cm))
                            img_count += 1
                        except:
                            pass
                elif elem['type'] == 'text':
                    try:
                        story.append(Paragraph(safe_text(elem['content']), styles['body']))
                    except:
                        pass

        story.append(Spacer(1, 0.5*cm))

    print(f"  圖片數: {img_count}")

    # 建立 PDF
    try:
        doc.build(story)
        print(f"  成功: {output_pdf}")
        return True
    except Exception as e:
        print(f"  失敗: {e}")
        return False

def main():
    init_font()

    pdf_dir = r"C:\真桌面\Claude code\ERP explore\CHM_PDF_v3"
    os.makedirs(pdf_dir, exist_ok=True)

    chm_list = [
        {
            'extract': r"C:\temp\chm_extract",
            'output': os.path.join(pdf_dir, "01_Trade_貿易模組.pdf"),
            'title_zh': "貿易模組操作說明",
            'title_en': "Trade Module"
        },
        {
            'extract': r"C:\temp\chm_acct",
            'output': os.path.join(pdf_dir, "02_Acct_會計模組.pdf"),
            'title_zh': "會計模組操作說明",
            'title_en': "Accounting Module"
        },
        {
            'extract': r"C:\temp\chm_stock",
            'output': os.path.join(pdf_dir, "03_Stock_庫存模組.pdf"),
            'title_zh': "庫存模組操作說明",
            'title_en': "Stock Module"
        },
        {
            'extract': r"C:\temp\chm_salary",
            'output': os.path.join(pdf_dir, "04_Salary_薪資模組.pdf"),
            'title_zh': "薪資模組操作說明",
            'title_en': "Salary Module"
        },
        {
            'extract': r"C:\temp\chm_prod",
            'output': os.path.join(pdf_dir, "05_Prod_生產模組.pdf"),
            'title_zh': "生產模組操作說明",
            'title_en': "Production Module"
        },
    ]

    print("\n" + "=" * 60)
    print("CHM 轉 PDF v3 (可點擊目錄)")
    print("=" * 60)

    results = []
    for item in chm_list:
        if os.path.exists(item['extract']):
            ok = convert_chm_to_pdf(
                item['extract'],
                item['output'],
                item['title_zh'],
                item['title_en']
            )
            results.append((item['title_zh'], ok))
        else:
            print(f"\n找不到: {item['extract']}")
            results.append((item['title_zh'], False))

    print("\n" + "=" * 60)
    print("轉換結果")
    print("=" * 60)
    for name, ok in results:
        status = "[OK]" if ok else "[X]"
        print(f"  {status} {name}")

if __name__ == "__main__":
    main()
