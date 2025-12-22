# -*- coding: utf-8 -*-
"""
建立貿易模組的輕量級索引系統
- 提取 39 個章節
- 生成 keywords.json（~800 tokens）
- 生成 toc.json（~500 tokens）
- 拆分為 Markdown chunks
"""

import os
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup

# 路徑設定（使用相對路徑）
BASE_DIR = Path(__file__).parent
HTML_FILE = BASE_DIR / "ERP說明文檔" / "CHM_HTML" / "01_Trade_貿易模組.html"
OUTPUT_DIR = BASE_DIR / "docs-index" / "trade-module"

def read_html():
    """讀取 HTML 文件"""
    with open(HTML_FILE, 'r', encoding='utf-8') as f:
        return f.read()

def extract_toc(html):
    """提取目錄結構"""
    soup = BeautifulSoup(html, 'html.parser')

    # 找到目錄區塊
    toc_div = soup.find('div', class_='toc')
    if not toc_div:
        print("找不到目錄區塊")
        return []

    toc = []
    links = toc_div.find_all('a')

    for link in links:
        href = link.get('href', '')
        title = link.get_text(strip=True)

        # 提取章節編號
        match = re.match(r'(\d+)\.\s*(.+)', title)
        if match:
            num = int(match.group(1))
            name = match.group(2)
            chapter_id = href.replace('#chapter-', '')

            toc.append({
                'id': f"ch{chapter_id.zfill(2)}",
                'num': num,
                'title': name
            })

    return toc

def extract_chapter_content(html, chapter_num):
    """提取單個章節的內容"""
    soup = BeautifulSoup(html, 'html.parser')

    chapter_div = soup.find('div', id=f'chapter-{chapter_num}')
    if not chapter_div:
        return None

    # 取得章節標題
    header = chapter_div.find('div', class_='chapter-header')
    title = header.get_text(strip=True) if header else f"Chapter {chapter_num}"

    # 取得內容
    content_div = chapter_div.find('div', class_='content')
    if not content_div:
        return None

    # 轉換為 Markdown
    markdown = f"# {title}\n\n"

    # 處理表格
    for table in content_div.find_all('table'):
        markdown += "\n"
        rows = table.find_all('tr')
        for i, row in enumerate(rows):
            cells = row.find_all(['th', 'td'])
            markdown += "| " + " | ".join(cell.get_text(strip=True) for cell in cells) + " |\n"
            if i == 0:  # 表頭分隔線
                markdown += "| " + " | ".join(['---'] * len(cells)) + " |\n"
        markdown += "\n"

    # 處理段落
    for p in content_div.find_all('p'):
        text = p.get_text(strip=True)
        if text:
            markdown += f"{text}\n\n"

    return markdown

def extract_keywords(toc):
    """從章節標題提取關鍵字"""
    keywords = {}

    # 手動定義關鍵字映射（基於章節標題）
    keyword_patterns = {
        "上線": ["ch01", "ch06"],
        "流程": ["ch02", "ch03"],
        "功能鍵": ["ch04"],
        "查詢": ["ch05", "ch19", "ch20", "ch21"],
        "系統設定": ["ch07"],
        "公司": ["ch07"],
        "權限": ["ch07"],
        "幣別": ["ch07"],
        "客戶": ["ch08"],
        "廠商": ["ch08"],
        "產品": ["ch08"],
        "開帳": ["ch09"],
        "報價": ["ch11", "ch17"],
        "訂單": ["ch12", "ch20"],
        "採購": ["ch12", "ch21"],
        "出貨": ["ch12", "ch14", "ch18"],
        "組合": ["ch13"],
        "分批": ["ch14"],
        "分開包裝": ["ch15"],
        "佣金": ["ch16"],
        "INVOICE": ["ch18"],
        "追蹤": ["ch19", "ch20", "ch21"],
        "帳款": ["ch22", "ch23", "ch24"],
        "應收": ["ch23"],
        "應付": ["ch24"],
        "收支": ["ch25"],
        "預收": ["ch26"],
        "預付": ["ch26"],
        "訂金": ["ch26"],
        "加扣款": ["ch27"],
        "信用狀": ["ch28"],
        "備份": ["ch30"],
        "歷史": ["ch31"],
        "覆核": ["ch32"],
        "關帳": ["ch32"],
        "EXCEL": ["ch34"],
        "傳輸": ["ch35"],
        "排程": ["ch36"],
        "傳真": ["ch37"],
        "Q&A": ["ch38", "ch39"]
    }

    # 從標題自動提取
    for item in toc:
        title = item['title']
        ch_id = item['id']

        # 分詞（簡單版）
        words = re.findall(r'[\u4e00-\u9fff]+', title)
        for word in words:
            if len(word) >= 2:  # 至少 2 個字
                if word not in keywords:
                    keywords[word] = []
                if ch_id not in keywords[word]:
                    keywords[word].append(ch_id)

    # 合併手動定義的關鍵字
    for keyword, chapters in keyword_patterns.items():
        if keyword in keywords:
            keywords[keyword].extend([ch for ch in chapters if ch not in keywords[keyword]])
        else:
            keywords[keyword] = chapters

    return keywords

def main():
    print("="*60)
    print("建立貿易模組索引")
    print("="*60)

    # 建立輸出目錄
    os.makedirs(str(OUTPUT_DIR), exist_ok=True)
    os.makedirs(str(OUTPUT_DIR / "chunks"), exist_ok=True)

    # 讀取 HTML
    print("\n讀取 HTML...")
    html = read_html()

    # 提取目錄
    print("提取目錄...")
    toc = extract_toc(html)
    print(f"  找到 {len(toc)} 個章節")

    # 生成 toc.json
    toc_file = OUTPUT_DIR / "toc.json"
    with open(str(toc_file), 'w', encoding='utf-8') as f:
        json.dump({"chapters": toc}, f, ensure_ascii=False, indent=2)
    print(f"  [OK] toc.json")

    # 提取關鍵字
    print("\n提取關鍵字...")
    keywords = extract_keywords(toc)
    print(f"  找到 {len(keywords)} 個關鍵字")

    # 生成 keywords.json
    keywords_file = OUTPUT_DIR / "keywords.json"
    with open(str(keywords_file), 'w', encoding='utf-8') as f:
        json.dump(keywords, f, ensure_ascii=False, indent=2)
    print(f"  [OK] keywords.json")

    # 拆分章節
    print("\n拆分章節...")
    chunks_dir = OUTPUT_DIR / "chunks"

    for item in toc:
        ch_num = item['num']
        ch_id = item['id']

        markdown = extract_chapter_content(html, ch_num)
        if markdown:
            chunk_file = chunks_dir / f"{ch_id}.md"
            with open(str(chunk_file), 'w', encoding='utf-8') as f:
                f.write(markdown)
            print(f"  [OK] {ch_id}: {item['title']}")
        else:
            print(f"  [FAIL] {ch_id}: 無法提取內容")

    # 計算檔案大小和 token 估計
    print("\n"+"="*60)
    print("索引統計")
    print("="*60)

    toc_size = os.path.getsize(toc_file)
    keywords_size = os.path.getsize(keywords_file)

    print(f"toc.json:      {toc_size:,} bytes (~{toc_size//4} tokens)")
    print(f"keywords.json: {keywords_size:,} bytes (~{keywords_size//4} tokens)")

    total_chunk_size = sum(
        os.path.getsize(str(chunks_dir / f))
        for f in os.listdir(str(chunks_dir))
    )
    avg_chunk_size = total_chunk_size // len(toc)

    print(f"\n章節總大小:    {total_chunk_size:,} bytes")
    print(f"平均章節大小:  {avg_chunk_size:,} bytes (~{avg_chunk_size//4} tokens)")

    print("\n[SUCCESS] 完成！")

if __name__ == "__main__":
    main()
