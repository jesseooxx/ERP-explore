# -*- coding: utf-8 -*-
"""
將 trade_1.chm 轉換為 PDF (使用已解壓的檔案)
"""

import os
import re
from pathlib import Path
from html.parser import HTMLParser
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_LEFT, TA_CENTER

def register_chinese_font():
    """註冊中文字體"""
    font_paths = [
        (r"C:\Windows\Fonts\msjh.ttc", 0),      # 微軟正黑體
        (r"C:\Windows\Fonts\mingliu.ttc", 0),   # 細明體
        (r"C:\Windows\Fonts\kaiu.ttf", None),   # 標楷體
    ]

    for font_info in font_paths:
        font_path = font_info[0]
        subfont = font_info[1] if len(font_info) > 1 else None

        if os.path.exists(font_path):
            try:
                if subfont is not None and font_path.endswith('.ttc'):
                    pdfmetrics.registerFont(TTFont('Chinese', font_path, subfontIndex=subfont))
                else:
                    pdfmetrics.registerFont(TTFont('Chinese', font_path))
                print(f"已註冊字體: {font_path}")
                return 'Chinese'
            except Exception as e:
                print(f"註冊字體失敗 {font_path}: {e}")
                continue

    return 'Helvetica'

def read_html_big5(file_path):
    """使用 Big5 編碼讀取 HTML"""
    encodings = ['big5', 'cp950', 'utf-8']

    for enc in encodings:
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()
            content = raw.decode(enc, errors='replace')
            if content.count('\ufffd') < 50:  # 允許少量替換
                return content
        except:
            continue

    return None

def html_to_text(html_content):
    """簡單的 HTML 轉文字"""
    # 移除 script 和 style
    text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)

    # 處理換行標籤
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</div>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</tr>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</li>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</h[1-6]>', '\n\n', text, flags=re.IGNORECASE)

    # 移除所有標籤
    text = re.sub(r'<[^>]+>', '', text)

    # 清理 HTML 實體
    text = text.replace('&nbsp;', ' ')
    text = text.replace('&amp;', '&')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    text = text.replace('&quot;', '"')

    # 清理多餘空白
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n[ \t]+', '\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()

def parse_hhc_big5(hhc_path):
    """解析 HHC 目錄"""
    content = read_html_big5(hhc_path)
    if not content:
        return []

    chapters = []
    # 匹配章節
    pattern = r'<param\s+name="Name"\s+value="([^"]+)"[^>]*>.*?<param\s+name="Local"\s+value="([^"]+)"'
    matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)

    for name, local in matches:
        chapters.append({'name': name, 'file': local})

    return chapters

def safe_text(text):
    """清理文字以供 PDF 使用"""
    if not text:
        return ""
    # 移除控制字符
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
    # 轉義 XML 特殊字符
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text

def create_trade_pdf():
    """建立 Trade 模組 PDF"""

    extract_dir = r"C:\temp\chm_extract"
    output_pdf = r"C:\真桌面\Claude code\ERP explore\CHM_PDF\trade_1_貿易模組說明.pdf"

    # 確保輸出目錄存在
    os.makedirs(os.path.dirname(output_pdf), exist_ok=True)

    # 註冊字體
    font_name = register_chinese_font()

    # 解析目錄
    hhc_path = os.path.join(extract_dir, "Trade_1.hhc")
    chapters = parse_hhc_big5(hhc_path)
    print(f"找到 {len(chapters)} 個章節")

    # 如果沒找到章節，手動建立
    if not chapters:
        htm_files = sorted(Path(extract_dir).glob("*.htm"))
        chapters = [{'name': f.stem, 'file': f.name} for f in htm_files]

    # 建立 PDF
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'Title',
        fontName=font_name,
        fontSize=24,
        alignment=TA_CENTER,
        spaceAfter=30
    )

    heading_style = ParagraphStyle(
        'Heading',
        fontName=font_name,
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor='#0066CC'
    )

    body_style = ParagraphStyle(
        'Body',
        fontName=font_name,
        fontSize=10,
        leading=14,
        spaceBefore=4,
        spaceAfter=4
    )

    story = []

    # 標題頁
    story.append(Paragraph(safe_text("DataWin ERP 貿易模組說明"), title_style))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(safe_text("Trade Module Documentation"), body_style))
    story.append(Paragraph(safe_text("自動轉換自 trade_1.chm"), body_style))
    story.append(PageBreak())

    # 目錄頁
    story.append(Paragraph(safe_text("目錄"), heading_style))
    for i, ch in enumerate(chapters, 1):
        story.append(Paragraph(safe_text(f"{i}. {ch['name']}"), body_style))
    story.append(PageBreak())

    # 內容頁
    for ch in chapters:
        ch_name = ch['name']
        ch_file = ch['file']

        story.append(Paragraph(safe_text(ch_name), heading_style))

        # 讀取 HTML
        html_path = os.path.join(extract_dir, ch_file)
        if os.path.exists(html_path):
            content = read_html_big5(html_path)
            if content:
                text = html_to_text(content)
                # 分段
                for para in text.split('\n\n'):
                    para = para.strip()
                    if para and len(para) > 1:
                        try:
                            story.append(Paragraph(safe_text(para), body_style))
                        except Exception as e:
                            print(f"段落錯誤: {e}")

        story.append(Spacer(1, 0.5*cm))

    # 建立 PDF
    try:
        doc.build(story)
        print(f"\n成功建立: {output_pdf}")
        return True
    except Exception as e:
        print(f"建立 PDF 失敗: {e}")
        return False

if __name__ == "__main__":
    create_trade_pdf()
