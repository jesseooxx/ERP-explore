# -*- coding: utf-8 -*-
"""
將所有 CHM 說明文件轉換為 PDF
支援 Big5 編碼的繁體中文
"""

import os
import re
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER

# 全域字體名稱
FONT_NAME = 'Helvetica'

def init_font():
    """初始化中文字體"""
    global FONT_NAME
    font_paths = [
        (r"C:\Windows\Fonts\msjh.ttc", 0),
        (r"C:\Windows\Fonts\mingliu.ttc", 0),
    ]

    for font_path, idx in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('Chinese', font_path, subfontIndex=idx))
                FONT_NAME = 'Chinese'
                print(f"字體已載入: {font_path}")
                return
            except:
                continue

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
    """移除 HTML 標籤"""
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

def safe(text):
    """清理文字"""
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(text))
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def get_chapters(hhc_path):
    """從 HHC 取得章節"""
    content = read_big5(hhc_path)
    pattern = r'<param\s+name="Name"\s+value="([^"]+)".*?<param\s+name="Local"\s+value="([^"]+)"'
    return [{'name': m[0], 'file': m[1]} for m in re.findall(pattern, content, re.I|re.DOTALL)]

def make_pdf(extract_dir, output_pdf, title_zh, title_en):
    """建立 PDF"""
    # 找 HHC
    hhc_files = list(Path(extract_dir).glob("*.hhc"))
    if not hhc_files:
        print(f"  找不到 HHC: {extract_dir}")
        return False

    chapters = get_chapters(str(hhc_files[0]))
    if not chapters:
        htm_files = sorted(Path(extract_dir).glob("*.htm"))
        chapters = [{'name': f.stem, 'file': f.name} for f in htm_files]

    print(f"  章節數: {len(chapters)}")

    # 建立文件
    doc = SimpleDocTemplate(output_pdf, pagesize=A4,
                           rightMargin=2*cm, leftMargin=2*cm,
                           topMargin=2*cm, bottomMargin=2*cm)

    title_style = ParagraphStyle('T', fontName=FONT_NAME, fontSize=22, alignment=TA_CENTER, spaceAfter=20)
    h_style = ParagraphStyle('H', fontName=FONT_NAME, fontSize=13, spaceBefore=15, spaceAfter=8, textColor='#0055AA')
    p_style = ParagraphStyle('P', fontName=FONT_NAME, fontSize=10, leading=14, spaceBefore=3, spaceAfter=3)

    story = []

    # 標題頁
    story.append(Paragraph(safe(title_zh), title_style))
    story.append(Paragraph(safe(title_en), p_style))
    story.append(Paragraph(safe("DataWin ERP 系統說明文件"), p_style))
    story.append(PageBreak())

    # 目錄
    story.append(Paragraph(safe("目錄"), h_style))
    for i, ch in enumerate(chapters, 1):
        story.append(Paragraph(safe(f"{i}. {ch['name']}"), p_style))
    story.append(PageBreak())

    # 內容
    for ch in chapters:
        story.append(Paragraph(safe(ch['name']), h_style))
        htm_path = os.path.join(extract_dir, ch['file'])
        if os.path.exists(htm_path):
            html = read_big5(htm_path)
            text = strip_html(html)
            for para in text.split('\n\n'):
                para = para.strip()
                if para and len(para) > 1:
                    try:
                        story.append(Paragraph(safe(para), p_style))
                    except:
                        pass
        story.append(Spacer(1, 0.3*cm))

    try:
        doc.build(story)
        print(f"  已建立: {output_pdf}")
        return True
    except Exception as e:
        print(f"  失敗: {e}")
        return False

def main():
    init_font()

    pdf_dir = r"C:\真桌面\Claude code\ERP explore\CHM_PDF"
    os.makedirs(pdf_dir, exist_ok=True)

    # CHM 資訊
    chm_list = [
        {
            'extract': r"C:\temp\chm_extract",
            'output': os.path.join(pdf_dir, "01_Trade_貿易模組.pdf"),
            'title_zh': "貿易模組說明",
            'title_en': "Trade Module"
        },
        {
            'extract': r"C:\temp\chm_acct",
            'output': os.path.join(pdf_dir, "02_Acct_會計模組.pdf"),
            'title_zh': "會計模組說明",
            'title_en': "Accounting Module"
        },
        {
            'extract': r"C:\temp\chm_stock",
            'output': os.path.join(pdf_dir, "03_Stock_庫存模組.pdf"),
            'title_zh': "庫存模組說明",
            'title_en': "Stock Module"
        },
        {
            'extract': r"C:\temp\chm_salary",
            'output': os.path.join(pdf_dir, "04_Salary_薪資模組.pdf"),
            'title_zh': "薪資模組說明",
            'title_en': "Salary Module"
        },
        {
            'extract': r"C:\temp\chm_prod",
            'output': os.path.join(pdf_dir, "05_Prod_生產模組.pdf"),
            'title_zh': "生產模組說明",
            'title_en': "Production Module"
        },
    ]

    print("=" * 50)
    print("CHM 轉 PDF 轉換器")
    print("=" * 50)

    results = []
    for item in chm_list:
        print(f"\n處理: {item['title_zh']}")
        if os.path.exists(item['extract']):
            ok = make_pdf(item['extract'], item['output'], item['title_zh'], item['title_en'])
            results.append((item['title_zh'], ok))
        else:
            print(f"  目錄不存在: {item['extract']}")
            results.append((item['title_zh'], False))

    print("\n" + "=" * 50)
    print("轉換結果:")
    print("=" * 50)
    for name, ok in results:
        print(f"  {name}: {'成功' if ok else '失敗'}")

if __name__ == "__main__":
    main()
