# -*- coding: utf-8 -*-
"""
CHM to PDF Converter for DataWin ERP Help Files
將 CHM 說明文件轉換為 PDF，正確處理 Big5 編碼
"""

import os
import subprocess
import re
from pathlib import Path
from html.parser import HTMLParser
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# 註冊中文字體
def register_chinese_font():
    """註冊中文字體"""
    font_paths = [
        r"C:\Windows\Fonts\msjh.ttc",      # 微軟正黑體
        r"C:\Windows\Fonts\mingliu.ttc",   # 細明體
        r"C:\Windows\Fonts\kaiu.ttf",      # 標楷體
        r"C:\Windows\Fonts\simsun.ttc",    # 宋體
    ]

    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('Chinese', font_path))
                print(f"已註冊字體: {font_path}")
                return 'Chinese'
            except Exception as e:
                print(f"註冊字體失敗 {font_path}: {e}")
                continue

    print("警告: 無法找到中文字體，將使用預設字體")
    return 'Helvetica'

class HTMLTextExtractor(HTMLParser):
    """從 HTML 提取純文字"""
    def __init__(self):
        super().__init__()
        self.text = []
        self.current_tag = None
        self.skip_tags = {'script', 'style', 'head', 'meta', 'link'}
        self.in_skip = False

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag.lower()
        if self.current_tag in self.skip_tags:
            self.in_skip = True
        if self.current_tag in ['p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3', 'h4']:
            self.text.append('\n')

    def handle_endtag(self, tag):
        if tag.lower() in self.skip_tags:
            self.in_skip = False
        if tag.lower() in ['p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'h4']:
            self.text.append('\n')

    def handle_data(self, data):
        if not self.in_skip:
            cleaned = data.strip()
            if cleaned:
                self.text.append(cleaned + ' ')

    def get_text(self):
        return ''.join(self.text)

def extract_chm(chm_path, output_dir):
    """使用 hh.exe 解壓 CHM 檔案"""
    os.makedirs(output_dir, exist_ok=True)

    # 使用 hh.exe -decompile
    cmd = f'hh.exe -decompile "{output_dir}" "{chm_path}"'
    try:
        subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        print(f"已解壓: {chm_path} -> {output_dir}")
        return True
    except Exception as e:
        print(f"解壓失敗: {e}")
        return False

def read_html_with_encoding(file_path):
    """嘗試多種編碼讀取 HTML 檔案"""
    encodings = ['big5', 'cp950', 'gb2312', 'gbk', 'utf-8', 'utf-8-sig']

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                content = f.read()
                # 檢查是否有太多替換字符
                if content.count('\ufffd') < len(content) * 0.1:
                    return content, encoding
        except Exception:
            continue

    # 最後嘗試二進位讀取
    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
            return raw.decode('big5', errors='replace'), 'big5-fallback'
    except:
        return None, None

def parse_hhc(hhc_path):
    """解析 HHC 目錄檔案，提取章節結構"""
    content, encoding = read_html_with_encoding(hhc_path)
    if not content:
        return []

    chapters = []
    # 使用正則表達式提取章節
    pattern = r'<param\s+name="Name"\s+value="([^"]+)"[^>]*>.*?<param\s+name="Local"\s+value="([^"]+)"'
    matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)

    for name, local in matches:
        chapters.append({
            'name': name,
            'file': local
        })

    return chapters

def html_to_text(html_content):
    """將 HTML 轉換為純文字"""
    parser = HTMLTextExtractor()
    try:
        parser.feed(html_content)
        text = parser.get_text()
        # 清理多餘空白
        text = re.sub(r'\n\s*\n', '\n\n', text)
        text = re.sub(r'[ \t]+', ' ', text)
        return text.strip()
    except:
        # 如果解析失敗，使用簡單的標籤移除
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

def create_pdf(chapters, extracted_dir, output_pdf, title, font_name):
    """建立 PDF 文件"""
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    # 建立樣式
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'ChineseTitle',
        parent=styles['Title'],
        fontName=font_name,
        fontSize=24,
        alignment=TA_CENTER,
        spaceAfter=30
    )

    heading_style = ParagraphStyle(
        'ChineseHeading',
        parent=styles['Heading1'],
        fontName=font_name,
        fontSize=16,
        spaceBefore=20,
        spaceAfter=10
    )

    body_style = ParagraphStyle(
        'ChineseBody',
        parent=styles['Normal'],
        fontName=font_name,
        fontSize=11,
        leading=16,
        spaceBefore=6,
        spaceAfter=6
    )

    story = []

    # 標題頁
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("DataWin ERP 系統說明文件", body_style))
    story.append(Paragraph("自動轉換自 CHM 格式", body_style))
    story.append(PageBreak())

    # 目錄
    story.append(Paragraph("目錄", heading_style))
    for i, chapter in enumerate(chapters, 1):
        chapter_name = chapter['name']
        # 清理 XML 特殊字符
        chapter_name = chapter_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        story.append(Paragraph(f"{i}. {chapter_name}", body_style))
    story.append(PageBreak())

    # 內容
    for chapter in chapters:
        chapter_name = chapter['name']
        chapter_file = chapter['file']

        # 清理章節名稱
        safe_name = chapter_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        story.append(Paragraph(safe_name, heading_style))

        # 讀取 HTML 內容
        html_path = os.path.join(extracted_dir, chapter_file)
        if os.path.exists(html_path):
            content, _ = read_html_with_encoding(html_path)
            if content:
                text = html_to_text(content)
                # 分段處理
                paragraphs = text.split('\n\n')
                for para in paragraphs:
                    para = para.strip()
                    if para:
                        # 清理 XML 特殊字符
                        safe_para = para.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        try:
                            story.append(Paragraph(safe_para, body_style))
                        except:
                            # 如果段落有問題，跳過
                            pass

        story.append(Spacer(1, 1*cm))

    # 建立 PDF
    try:
        doc.build(story)
        print(f"已建立 PDF: {output_pdf}")
        return True
    except Exception as e:
        print(f"建立 PDF 失敗: {e}")
        return False

def process_chm(chm_path, output_dir, pdf_output_dir):
    """處理單一 CHM 檔案"""
    chm_name = Path(chm_path).stem
    extract_dir = os.path.join(output_dir, chm_name)

    print(f"\n處理: {chm_name}")
    print("-" * 50)

    # 解壓 CHM
    if not extract_chm(chm_path, extract_dir):
        return False

    # 尋找 HHC 檔案
    hhc_files = list(Path(extract_dir).glob("*.hhc"))
    if not hhc_files:
        print(f"找不到 HHC 目錄檔案")
        return False

    hhc_path = str(hhc_files[0])
    print(f"使用目錄檔案: {hhc_path}")

    # 解析章節
    chapters = parse_hhc(hhc_path)
    print(f"找到 {len(chapters)} 個章節")

    if not chapters:
        # 如果沒有章節，嘗試列出所有 HTML
        htm_files = list(Path(extract_dir).glob("*.htm"))
        chapters = [{'name': f.stem, 'file': f.name} for f in htm_files]
        print(f"使用 {len(chapters)} 個 HTML 檔案")

    # 註冊中文字體
    font_name = register_chinese_font()

    # 建立 PDF
    pdf_path = os.path.join(pdf_output_dir, f"{chm_name}.pdf")
    title = chm_name.replace('_', ' ').title()

    return create_pdf(chapters, extract_dir, pdf_path, title, font_name)

def main():
    # 設定路徑
    chm_dir = r"X:\EXE"
    output_dir = r"C:\temp\chm_extracted"
    pdf_output_dir = r"C:\真桌面\Claude code\ERP explore\CHM_PDF"

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(pdf_output_dir, exist_ok=True)

    # CHM 檔案清單
    chm_files = [
        "trade_1.chm",
        "Acct_1.chm",
        "prod_1.chm",
        "salary_1.chm",
        "stock_1.chm",
        "GOLDENTOP_1.chm"
    ]

    results = []
    for chm_file in chm_files:
        chm_path = os.path.join(chm_dir, chm_file)
        if os.path.exists(chm_path):
            success = process_chm(chm_path, output_dir, pdf_output_dir)
            results.append((chm_file, success))
        else:
            print(f"找不到: {chm_path}")
            results.append((chm_file, False))

    # 總結
    print("\n" + "=" * 50)
    print("轉換結果:")
    print("=" * 50)
    for chm_file, success in results:
        status = "成功" if success else "失敗"
        print(f"  {chm_file}: {status}")

if __name__ == "__main__":
    main()
