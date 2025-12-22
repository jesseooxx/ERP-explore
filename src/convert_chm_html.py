# -*- coding: utf-8 -*-
"""
CHM 轉 HTML 單檔轉換器
- 圖片內嵌 base64（單檔即可瀏覽）
- 可點擊目錄跳轉
- 保留表格結構
- 頁首顯示章節名稱
"""

import os
import re
import base64
from pathlib import Path

def read_big5(path):
    """讀取 Big5 編碼檔案"""
    for enc in ['big5', 'cp950', 'utf-8']:
        try:
            with open(path, 'rb') as f:
                return f.read().decode(enc, errors='replace')
        except:
            pass
    return ""

def get_chapters(hhc_path):
    """從 HHC 取得章節"""
    content = read_big5(hhc_path)
    pattern = r'<param\s+name="Name"\s+value="([^"]+)".*?<param\s+name="Local"\s+value="([^"]+)"'
    return [{'name': m[0], 'file': m[1]} for m in re.findall(pattern, content, re.I|re.DOTALL)]

def image_to_base64(img_path):
    """將圖片轉為 base64"""
    try:
        ext = os.path.splitext(img_path)[1].lower()
        mime_types = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.png': 'image/png'}
        mime = mime_types.get(ext, 'image/jpeg')

        with open(img_path, 'rb') as f:
            data = base64.b64encode(f.read()).decode('ascii')
        return f'data:{mime};base64,{data}'
    except:
        return None

def clean_html_content(html, extract_dir):
    """清理 HTML 內容，保留表格，內嵌圖片"""
    # 移除 head 區塊
    html = re.sub(r'<head[^>]*>.*?</head>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<html[^>]*>', '', html, flags=re.I)
    html = re.sub(r'</html>', '', html, flags=re.I)
    html = re.sub(r'<body[^>]*>', '', html, flags=re.I)
    html = re.sub(r'</body>', '', html, flags=re.I)
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.I)

    # 移除導航連結圖片 (005.gif 等)
    html = re.sub(r'<a[^>]*>\s*<img[^>]*005\.gif[^>]*>\s*</a>', '', html, flags=re.I)

    # 轉換圖片為 base64
    def replace_img(match):
        full_tag = match.group(0)
        src_match = re.search(r'src=["\']([^"\']+)["\']', full_tag, re.I)
        if src_match:
            src = src_match.group(1)
            img_path = os.path.join(extract_dir, src.replace('/', os.sep))
            if os.path.exists(img_path):
                base64_data = image_to_base64(img_path)
                if base64_data:
                    # 保留其他屬性，只替換 src
                    new_tag = re.sub(r'src=["\'][^"\']+["\']', f'src="{base64_data}"', full_tag)
                    return f'<div class="img-container">{new_tag}</div>'
        return ''

    html = re.sub(r'<img[^>]*>', replace_img, html, flags=re.I)

    # 移除空連結
    html = re.sub(r'<a[^>]*>\s*</a>', '', html, flags=re.I)

    # 清理多餘空白
    html = re.sub(r'\n\s*\n\s*\n', '\n\n', html)

    return html.strip()

def generate_html(extract_dir, output_html, title_zh, title_en):
    """生成單檔 HTML"""

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

    # 計算圖片數
    img_count = 0

    # HTML 模板
    html_parts = []

    # CSS 樣式
    css = '''
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: "Microsoft JhengHei", "微軟正黑體", sans-serif;
            line-height: 1.8;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        /* 封面 */
        .cover {
            text-align: center;
            padding: 60px 0;
            border-bottom: 3px solid #0066cc;
            margin-bottom: 40px;
        }
        .cover h1 {
            color: #003366;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .cover .subtitle {
            color: #666;
            font-size: 1.2em;
        }
        /* 目錄 */
        .toc {
            background: #f8f9fa;
            padding: 30px;
            margin-bottom: 40px;
            border-radius: 8px;
        }
        .toc h2 {
            color: #003366;
            border-bottom: 2px solid #0066cc;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .toc-hint {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 15px;
        }
        .toc ul {
            list-style: none;
            padding: 0;
            column-count: 2;
            column-gap: 30px;
        }
        .toc li {
            padding: 5px 0;
            break-inside: avoid;
        }
        .toc a {
            color: #0066cc;
            text-decoration: none;
            display: block;
            padding: 5px 10px;
            border-radius: 4px;
            transition: background 0.2s;
        }
        .toc a:hover {
            background: #e8f0fe;
        }
        /* 章節 */
        .chapter {
            margin-bottom: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .chapter-header {
            position: sticky;
            top: 0;
            background: linear-gradient(135deg, #0066cc, #004499);
            color: white;
            padding: 15px 20px;
            margin: -20px -40px 20px -40px;
            font-size: 1.3em;
            font-weight: bold;
            z-index: 100;
        }
        .chapter-header a {
            color: white;
            text-decoration: none;
        }
        .chapter-header .back-to-toc {
            float: right;
            font-size: 0.8em;
            opacity: 0.8;
        }
        .chapter-header .back-to-toc:hover {
            opacity: 1;
        }
        /* 內容 */
        .content {
            padding: 10px 0;
        }
        .content p {
            margin: 10px 0;
            text-align: justify;
        }
        .content table {
            border-collapse: collapse;
            width: 100%;
            margin: 15px 0;
            font-size: 0.95em;
        }
        .content th, .content td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        .content th {
            background: #f0f5ff;
        }
        .content tr:nth-child(even) {
            background: #fafafa;
        }
        /* 圖片 */
        .img-container {
            text-align: center;
            margin: 20px 0;
        }
        .img-container img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        /* 返回頂部 */
        .back-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #0066cc;
            color: white;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            text-align: center;
            line-height: 50px;
            text-decoration: none;
            font-size: 1.5em;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            opacity: 0.8;
        }
        .back-top:hover {
            opacity: 1;
        }
        /* 列印樣式 */
        @media print {
            .chapter-header { position: static; }
            .back-top { display: none; }
            .toc ul { column-count: 1; }
        }
    </style>
    '''

    # 開始 HTML
    html_parts.append(f'''<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title_zh} - DataWin ERP</title>
    {css}
</head>
<body>
<div class="container">
    <!-- 封面 -->
    <div class="cover" id="top">
        <h1>{title_zh}</h1>
        <div class="subtitle">{title_en}</div>
        <div class="subtitle">DataWin ERP 系統說明文件</div>
    </div>

    <!-- 目錄 -->
    <div class="toc" id="toc">
        <h2>目 錄</h2>
        <div class="toc-hint">點擊章節名稱跳轉</div>
        <ul>
''')

    # 目錄項目
    for i, ch in enumerate(chapters, 1):
        html_parts.append(f'            <li><a href="#chapter-{i}">{i}. {ch["name"]}</a></li>\n')

    html_parts.append('''        </ul>
    </div>

    <!-- 內容 -->
''')

    # 章節內容
    for i, ch in enumerate(chapters, 1):
        ch_name = ch['name']

        html_parts.append(f'''
    <div class="chapter" id="chapter-{i}">
        <div class="chapter-header">
            <a href="#toc" class="back-to-toc">↑ 返回目錄</a>
            {i}. {ch_name}
        </div>
        <div class="content">
''')

        # 讀取並處理 HTML 內容
        htm_path = os.path.join(extract_dir, ch['file'])
        if os.path.exists(htm_path):
            html_content = read_big5(htm_path)
            cleaned = clean_html_content(html_content, extract_dir)

            # 計算圖片數
            img_count += len(re.findall(r'<img[^>]*>', cleaned, re.I))

            html_parts.append(cleaned)

        html_parts.append('''
        </div>
    </div>
''')

    # 結尾
    html_parts.append('''
    <a href="#top" class="back-top">↑</a>
</div>
</body>
</html>
''')

    # 寫入檔案
    try:
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(''.join(html_parts))
        print(f"  圖片數: {img_count}")
        print(f"  成功: {output_html}")
        return True
    except Exception as e:
        print(f"  失敗: {e}")
        return False

def main():
    output_dir = r"C:\真桌面\Claude code\ERP explore\CHM_HTML"
    os.makedirs(output_dir, exist_ok=True)

    chm_list = [
        {
            'extract': r"C:\temp\chm_extract",
            'output': os.path.join(output_dir, "01_Trade_貿易模組.html"),
            'title_zh': "貿易模組操作說明",
            'title_en': "Trade Module"
        },
        {
            'extract': r"C:\temp\chm_acct",
            'output': os.path.join(output_dir, "02_Acct_會計模組.html"),
            'title_zh': "會計模組操作說明",
            'title_en': "Accounting Module"
        },
        {
            'extract': r"C:\temp\chm_stock",
            'output': os.path.join(output_dir, "03_Stock_庫存模組.html"),
            'title_zh': "庫存模組操作說明",
            'title_en': "Stock Module"
        },
        {
            'extract': r"C:\temp\chm_salary",
            'output': os.path.join(output_dir, "04_Salary_薪資模組.html"),
            'title_zh': "薪資模組操作說明",
            'title_en': "Salary Module"
        },
        {
            'extract': r"C:\temp\chm_prod",
            'output': os.path.join(output_dir, "05_Prod_生產模組.html"),
            'title_zh': "生產模組操作說明",
            'title_en': "Production Module"
        },
    ]

    print("\n" + "=" * 60)
    print("CHM 轉 HTML 單檔")
    print("=" * 60)

    results = []
    for item in chm_list:
        if os.path.exists(item['extract']):
            ok = generate_html(
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
