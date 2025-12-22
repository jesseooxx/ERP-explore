# -*- coding: utf-8 -*-
"""
CHM 轉 PDF 轉換器 v2
- 支援圖片嵌入
- 改進排版（適當空行）
- 正確處理 Big5 編碼
"""

import os
import re
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Image, KeepTogether, ListFlowable, ListItem
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor
from PIL import Image as PILImage
import io

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
        (r"C:\Windows\Fonts\msjh.ttc", 0),      # 微軟正黑體
        (r"C:\Windows\Fonts\mingliu.ttc", 0),   # 細明體
    ]
    for path, idx in font_paths:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont('Chinese', path, subfontIndex=idx))
                FONT_NAME = 'Chinese'
                print(f"字體: {path}")
                return
            except:
                pass

def read_big5(path):
    """讀取 Big5 編碼檔案"""
    for enc in ['big5', 'cp950', 'utf-8']:
        try:
            with open(path, 'rb') as f:
                content = f.read().decode(enc, errors='replace')
                if content.count('\ufffd') < 50:
                    return content
        except:
            pass
    return ""

def safe_text(text):
    """清理文字供 PDF 使用"""
    if not text:
        return ""
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(text))
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return text

def get_image_size(img_path, max_width=None, max_height=None):
    """計算圖片尺寸，保持比例"""
    if max_width is None:
        max_width = CONTENT_WIDTH
    if max_height is None:
        max_height = 12 * cm

    try:
        with PILImage.open(img_path) as img:
            w, h = img.size
            # 計算縮放比例
            ratio = min(max_width / w, max_height / h, 1.0)
            return w * ratio, h * ratio
    except:
        return max_width * 0.5, max_height * 0.3

def extract_content_with_images(html_content, base_dir):
    """從 HTML 提取內容，包含圖片標記"""
    elements = []

    # 移除 script 和 style
    html = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL|re.I)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    # 分割成段落和圖片
    # 先標記圖片位置
    img_pattern = r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>'

    parts = re.split(img_pattern, html, flags=re.I)

    i = 0
    while i < len(parts):
        part = parts[i]

        # 檢查是否是圖片路徑
        if i > 0 and i % 2 == 1:
            # 這是圖片路徑
            img_src = part
            # 處理相對路徑
            if not os.path.isabs(img_src):
                # 嘗試多個可能的路徑
                possible_paths = [
                    os.path.join(base_dir, img_src),
                    os.path.join(base_dir, 'picture', os.path.basename(img_src)),
                    os.path.join(base_dir, os.path.basename(img_src)),
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        elements.append(('image', p))
                        break
        else:
            # 這是文字內容
            text = strip_html_tags(part)
            if text.strip():
                elements.append(('text', text))

        i += 1

    return elements

def strip_html_tags(html):
    """移除 HTML 標籤，保留結構"""
    # 標題轉換
    html = re.sub(r'<h[1-3][^>]*>(.*?)</h[1-3]>', r'\n\n【\1】\n\n', html, flags=re.I|re.DOTALL)
    html = re.sub(r'<h[4-6][^>]*>(.*?)</h[4-6]>', r'\n\n\1\n\n', html, flags=re.I|re.DOTALL)

    # 段落和換行
    html = re.sub(r'<br\s*/?>', '\n', html, flags=re.I)
    html = re.sub(r'</p>', '\n\n', html, flags=re.I)
    html = re.sub(r'<p[^>]*>', '\n', html, flags=re.I)
    html = re.sub(r'</div>', '\n', html, flags=re.I)
    html = re.sub(r'</tr>', '\n', html, flags=re.I)
    html = re.sub(r'</td>', '  ', html, flags=re.I)
    html = re.sub(r'</li>', '\n', html, flags=re.I)
    html = re.sub(r'<li[^>]*>', '• ', html, flags=re.I)

    # 移除所有標籤
    html = re.sub(r'<[^>]+>', '', html)

    # HTML 實體
    html = html.replace('&nbsp;', ' ')
    html = html.replace('&amp;', '&')
    html = html.replace('&lt;', '<')
    html = html.replace('&gt;', '>')
    html = html.replace('&quot;', '"')
    html = html.replace('&#39;', "'")

    # 清理空白
    html = re.sub(r'[ \t]+', ' ', html)
    html = re.sub(r'\n[ \t]+', '\n', html)
    html = re.sub(r'[ \t]+\n', '\n', html)
    html = re.sub(r'\n{4,}', '\n\n\n', html)

    return html.strip()

def get_chapters(hhc_path):
    """解析 HHC 目錄"""
    content = read_big5(hhc_path)
    pattern = r'<param\s+name="Name"\s+value="([^"]+)".*?<param\s+name="Local"\s+value="([^"]+)"'
    chapters = []
    for m in re.findall(pattern, content, re.I|re.DOTALL):
        chapters.append({'name': m[0], 'file': m[1]})
    return chapters

def create_styles():
    """建立文字樣式"""
    return {
        'title': ParagraphStyle(
            'Title',
            fontName=FONT_NAME,
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30,
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
        'chapter': ParagraphStyle(
            'Chapter',
            fontName=FONT_NAME,
            fontSize=16,
            spaceBefore=30,
            spaceAfter=15,
            textColor=HexColor('#0055AA'),
            borderWidth=1,
            borderColor=HexColor('#0055AA'),
            borderPadding=5,
            backColor=HexColor('#F0F5FF')
        ),
        'heading': ParagraphStyle(
            'Heading',
            fontName=FONT_NAME,
            fontSize=13,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor('#333333'),
        ),
        'body': ParagraphStyle(
            'Body',
            fontName=FONT_NAME,
            fontSize=10,
            leading=16,  # 行距
            spaceBefore=6,
            spaceAfter=6,
            firstLineIndent=0,
        ),
        'toc': ParagraphStyle(
            'TOC',
            fontName=FONT_NAME,
            fontSize=11,
            leading=18,
            spaceBefore=3,
            spaceAfter=3,
        ),
        'toc_title': ParagraphStyle(
            'TOCTitle',
            fontName=FONT_NAME,
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=HexColor('#003366')
        ),
    }

def convert_chm_to_pdf(extract_dir, output_pdf, title_zh, title_en):
    """轉換 CHM 為 PDF"""

    print(f"\n{'='*50}")
    print(f"處理: {title_zh}")
    print(f"{'='*50}")

    # 找 HHC
    hhc_files = list(Path(extract_dir).glob("*.hhc"))
    if not hhc_files:
        print(f"  錯誤: 找不到 HHC 檔案")
        return False

    chapters = get_chapters(str(hhc_files[0]))
    if not chapters:
        htm_files = sorted(Path(extract_dir).glob("*.htm"))
        chapters = [{'name': f.stem, 'file': f.name} for f in htm_files]

    print(f"  章節數: {len(chapters)}")

    # 找圖片目錄
    pic_dirs = ['picture', 'images', 'img', '.']
    pic_base = None
    for pd in pic_dirs:
        test_path = os.path.join(extract_dir, pd)
        if os.path.exists(test_path):
            pic_base = test_path
            break

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
    story.append(Paragraph(safe_text("自動轉換自 CHM 格式"), styles['subtitle']))
    story.append(PageBreak())

    # === 目錄 ===
    story.append(Paragraph(safe_text("目 錄"), styles['toc_title']))
    story.append(Spacer(1, 0.5*cm))
    for i, ch in enumerate(chapters, 1):
        toc_text = f"{i:2d}. {ch['name']}"
        story.append(Paragraph(safe_text(toc_text), styles['toc']))
    story.append(PageBreak())

    # === 內容 ===
    img_count = 0
    for ch_idx, ch in enumerate(chapters, 1):
        ch_name = ch['name']
        ch_file = ch['file']

        # 章節標題
        chapter_title = f"{ch_idx}. {ch_name}"
        story.append(Paragraph(safe_text(chapter_title), styles['chapter']))
        story.append(Spacer(1, 0.3*cm))

        # 讀取 HTML
        htm_path = os.path.join(extract_dir, ch_file)
        if not os.path.exists(htm_path):
            story.append(Paragraph(safe_text("(內容不可用)"), styles['body']))
            continue

        html_content = read_big5(htm_path)
        if not html_content:
            continue

        # 提取內容（包含圖片標記）
        elements = extract_content_with_images(html_content, extract_dir)

        for elem_type, elem_content in elements:
            if elem_type == 'image':
                # 插入圖片
                try:
                    img_path = elem_content
                    if os.path.exists(img_path):
                        w, h = get_image_size(img_path)
                        img = Image(img_path, width=w, height=h)
                        story.append(Spacer(1, 0.3*cm))
                        story.append(img)
                        story.append(Spacer(1, 0.3*cm))
                        img_count += 1
                except Exception as e:
                    pass  # 圖片載入失敗時跳過

            elif elem_type == 'text':
                # 插入文字段落
                text = elem_content.strip()
                if not text:
                    continue

                # 分段
                paragraphs = text.split('\n\n')
                for para in paragraphs:
                    para = para.strip()
                    if not para:
                        continue

                    # 檢查是否是標題格式 【...】
                    if para.startswith('【') and '】' in para:
                        story.append(Spacer(1, 0.3*cm))
                        story.append(Paragraph(safe_text(para), styles['heading']))
                        story.append(Spacer(1, 0.2*cm))
                    else:
                        # 處理單行換行
                        lines = para.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line:
                                try:
                                    story.append(Paragraph(safe_text(line), styles['body']))
                                except:
                                    pass

                        # 段落間空行
                        story.append(Spacer(1, 0.2*cm))

        # 章節結束空白
        story.append(Spacer(1, 0.5*cm))

    print(f"  圖片數: {img_count}")

    # 建立 PDF
    try:
        doc.build(story)
        print(f"  完成: {output_pdf}")
        return True
    except Exception as e:
        print(f"  錯誤: {e}")
        return False

def main():
    # 初始化字體
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
                break
            except Exception as e:
                print(f"字體錯誤: {e}")

    # 輸出目錄
    pdf_dir = r"C:\真桌面\Claude code\ERP explore\CHM_PDF"
    os.makedirs(pdf_dir, exist_ok=True)

    # CHM 清單
    chm_list = [
        {
            'extract': r"C:\temp\chm_extract",
            'output': os.path.join(pdf_dir, "01_Trade_貿易模組.pdf"),
            'title_zh': "貿易模組操作手冊",
            'title_en': "Trade Module User Manual"
        },
        {
            'extract': r"C:\temp\chm_acct",
            'output': os.path.join(pdf_dir, "02_Acct_會計模組.pdf"),
            'title_zh': "會計模組操作手冊",
            'title_en': "Accounting Module User Manual"
        },
        {
            'extract': r"C:\temp\chm_stock",
            'output': os.path.join(pdf_dir, "03_Stock_庫存模組.pdf"),
            'title_zh': "庫存模組操作手冊",
            'title_en': "Stock Module User Manual"
        },
        {
            'extract': r"C:\temp\chm_salary",
            'output': os.path.join(pdf_dir, "04_Salary_薪資模組.pdf"),
            'title_zh': "薪資模組操作手冊",
            'title_en': "Salary Module User Manual"
        },
        {
            'extract': r"C:\temp\chm_prod",
            'output': os.path.join(pdf_dir, "05_Prod_生產模組.pdf"),
            'title_zh': "生產模組操作手冊",
            'title_en': "Production Module User Manual"
        },
    ]

    print("\n" + "=" * 60)
    print("CHM 轉 PDF 轉換器 v2 (含圖片)")
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

    # 結果摘要
    print("\n" + "=" * 60)
    print("轉換結果摘要")
    print("=" * 60)
    for name, ok in results:
        status = "[OK] 成功" if ok else "[X] 失敗"
        print(f"  {name}: {status}")

if __name__ == "__main__":
    main()
