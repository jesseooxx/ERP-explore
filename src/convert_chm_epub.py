# -*- coding: utf-8 -*-
"""
CHM 轉 EPUB 轉換器
- 標準 EPUB 格式
- 自動目錄 (NCX/NAV)
- 保留表格結構
- 圖片內嵌
"""

import os
import re
import uuid
import zipfile
from pathlib import Path
from datetime import datetime

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

def get_mime_type(ext):
    """取得 MIME 類型"""
    types = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.png': 'image/png',
    }
    return types.get(ext.lower(), 'image/jpeg')

def clean_html_for_epub(html, chapter_images):
    """清理 HTML 內容供 EPUB 使用"""
    # 移除 head 區塊
    html = re.sub(r'<head[^>]*>.*?</head>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<html[^>]*>', '', html, flags=re.I)
    html = re.sub(r'</html>', '', html, flags=re.I)
    html = re.sub(r'<body[^>]*>', '', html, flags=re.I)
    html = re.sub(r'</body>', '', html, flags=re.I)
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL|re.I)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.I)

    # 移除導航連結
    html = re.sub(r'<a[^>]*>\s*<img[^>]*005\.gif[^>]*>\s*</a>', '', html, flags=re.I)

    # 轉換圖片路徑並收集圖片
    def replace_img(match):
        full_tag = match.group(0)
        src_match = re.search(r'src=["\']([^"\']+)["\']', full_tag, re.I)
        if src_match:
            src = src_match.group(1)
            # 轉換為 EPUB 內部路徑
            img_filename = os.path.basename(src)
            chapter_images.append(src)
            new_tag = re.sub(r'src=["\'][^"\']+["\']', f'src="images/{img_filename}"', full_tag)
            return f'<div class="img-container">{new_tag}</div>'
        return ''

    html = re.sub(r'<img[^>]*>', replace_img, html, flags=re.I)

    # 移除空連結和多餘標籤
    html = re.sub(r'<a[^>]*>\s*</a>', '', html, flags=re.I)
    html = re.sub(r'<font[^>]*>', '', html, flags=re.I)
    html = re.sub(r'</font>', '', html, flags=re.I)

    # 修復不合法的 HTML
    html = re.sub(r'<p([^>]*)>\s*<p', '<p\\1></p><p', html, flags=re.I)

    return html.strip()

def generate_epub(extract_dir, output_epub, title_zh, title_en):
    """生成 EPUB"""

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

    # 唯一識別碼
    book_id = str(uuid.uuid4())

    # 收集所有圖片
    all_images = set()

    # CSS 樣式
    css_content = '''
body {
    font-family: sans-serif;
    line-height: 1.8;
    padding: 1em;
}
h1 {
    color: #003366;
    text-align: center;
    border-bottom: 2px solid #0066cc;
    padding-bottom: 0.5em;
}
h2 {
    color: #0055aa;
    margin-top: 1.5em;
}
.chapter-title {
    color: #003366;
    font-size: 1.5em;
    border-bottom: 1px solid #ccc;
    padding-bottom: 0.3em;
    margin-bottom: 1em;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
}
th, td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
}
th {
    background: #f0f5ff;
}
.img-container {
    text-align: center;
    margin: 1em 0;
}
.img-container img {
    max-width: 100%;
    height: auto;
}
.toc-item {
    margin: 0.5em 0;
}
.toc-item a {
    color: #0066cc;
    text-decoration: none;
}
'''

    # 建立 EPUB (ZIP 格式)
    try:
        with zipfile.ZipFile(output_epub, 'w', zipfile.ZIP_DEFLATED) as epub:

            # 1. mimetype (必須是第一個，且不壓縮)
            epub.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)

            # 2. META-INF/container.xml
            container_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles>
        <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
    </rootfiles>
</container>'''
            epub.writestr('META-INF/container.xml', container_xml)

            # 3. OEBPS/style.css
            epub.writestr('OEBPS/style.css', css_content)

            # 4. 封面頁
            cover_html = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>{title_zh}</title>
    <link rel="stylesheet" type="text/css" href="style.css"/>
</head>
<body>
    <h1>{title_zh}</h1>
    <p style="text-align:center; color:#666;">{title_en}</p>
    <p style="text-align:center; color:#666;">DataWin ERP 系統說明文件</p>
</body>
</html>'''
            epub.writestr('OEBPS/cover.xhtml', cover_html)

            # 5. 目錄頁
            toc_items = []
            for i, ch in enumerate(chapters, 1):
                toc_items.append(f'<p class="toc-item"><a href="chapter_{i}.xhtml">{i}. {ch["name"]}</a></p>')

            toc_html = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>目錄</title>
    <link rel="stylesheet" type="text/css" href="style.css"/>
</head>
<body>
    <h1>目 錄</h1>
    {''.join(toc_items)}
</body>
</html>'''
            epub.writestr('OEBPS/toc.xhtml', toc_html)

            # 6. 章節內容
            for i, ch in enumerate(chapters, 1):
                ch_name = ch['name']
                chapter_images = []

                # 讀取並處理 HTML
                htm_path = os.path.join(extract_dir, ch['file'])
                content = ""
                if os.path.exists(htm_path):
                    html_content = read_big5(htm_path)
                    content = clean_html_for_epub(html_content, chapter_images)

                    # 記錄所有圖片
                    all_images.update(chapter_images)

                chapter_html = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>{ch_name}</title>
    <link rel="stylesheet" type="text/css" href="style.css"/>
</head>
<body>
    <h2 class="chapter-title">{ch_name}</h2>
    <div class="content">
        {content}
    </div>
</body>
</html>'''
                epub.writestr(f'OEBPS/chapter_{i}.xhtml', chapter_html)

            # 7. 加入圖片
            img_count = 0
            for img_src in all_images:
                img_path = os.path.join(extract_dir, img_src.replace('/', os.sep))
                if os.path.exists(img_path):
                    img_filename = os.path.basename(img_src)
                    try:
                        with open(img_path, 'rb') as f:
                            epub.writestr(f'OEBPS/images/{img_filename}', f.read())
                        img_count += 1
                    except:
                        pass

            print(f"  圖片數: {img_count}")

            # 8. content.opf (套件文件)
            manifest_items = [
                '<item id="style" href="style.css" media-type="text/css"/>',
                '<item id="cover" href="cover.xhtml" media-type="application/xhtml+xml"/>',
                '<item id="toc-page" href="toc.xhtml" media-type="application/xhtml+xml"/>',
                '<item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>',
            ]

            spine_items = [
                '<itemref idref="cover"/>',
                '<itemref idref="toc-page"/>',
            ]

            for i, ch in enumerate(chapters, 1):
                manifest_items.append(f'<item id="chapter_{i}" href="chapter_{i}.xhtml" media-type="application/xhtml+xml"/>')
                spine_items.append(f'<itemref idref="chapter_{i}"/>')

            # 圖片 manifest
            for img_src in all_images:
                img_filename = os.path.basename(img_src)
                img_id = re.sub(r'[^a-zA-Z0-9]', '_', img_filename)
                ext = os.path.splitext(img_filename)[1]
                mime = get_mime_type(ext)
                manifest_items.append(f'<item id="img_{img_id}" href="images/{img_filename}" media-type="{mime}"/>')

            content_opf = f'''<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="BookId">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
        <dc:identifier id="BookId">urn:uuid:{book_id}</dc:identifier>
        <dc:title>{title_zh}</dc:title>
        <dc:language>zh-TW</dc:language>
        <dc:creator>DataWin ERP</dc:creator>
        <dc:date>{datetime.now().strftime('%Y-%m-%d')}</dc:date>
        <meta property="dcterms:modified">{datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')}</meta>
    </metadata>
    <manifest>
        {chr(10).join('        ' + item for item in manifest_items)}
    </manifest>
    <spine toc="ncx">
        {chr(10).join('        ' + item for item in spine_items)}
    </spine>
</package>'''
            epub.writestr('OEBPS/content.opf', content_opf)

            # 9. toc.ncx (NCX 導航)
            nav_points = []
            for i, ch in enumerate(chapters, 1):
                nav_points.append(f'''
        <navPoint id="navpoint-{i+2}" playOrder="{i+2}">
            <navLabel><text>{i}. {ch['name']}</text></navLabel>
            <content src="chapter_{i}.xhtml"/>
        </navPoint>''')

            toc_ncx = f'''<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
    <head>
        <meta name="dtb:uid" content="urn:uuid:{book_id}"/>
        <meta name="dtb:depth" content="1"/>
        <meta name="dtb:totalPageCount" content="0"/>
        <meta name="dtb:maxPageNumber" content="0"/>
    </head>
    <docTitle><text>{title_zh}</text></docTitle>
    <navMap>
        <navPoint id="navpoint-1" playOrder="1">
            <navLabel><text>封面</text></navLabel>
            <content src="cover.xhtml"/>
        </navPoint>
        <navPoint id="navpoint-2" playOrder="2">
            <navLabel><text>目錄</text></navLabel>
            <content src="toc.xhtml"/>
        </navPoint>
        {''.join(nav_points)}
    </navMap>
</ncx>'''
            epub.writestr('OEBPS/toc.ncx', toc_ncx)

        print(f"  成功: {output_epub}")
        return True

    except Exception as e:
        print(f"  失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    output_dir = r"C:\真桌面\Claude code\ERP explore\CHM_EPUB"
    os.makedirs(output_dir, exist_ok=True)

    chm_list = [
        {
            'extract': r"C:\temp\chm_extract",
            'output': os.path.join(output_dir, "01_Trade_貿易模組.epub"),
            'title_zh': "貿易模組操作說明",
            'title_en': "Trade Module"
        },
        {
            'extract': r"C:\temp\chm_acct",
            'output': os.path.join(output_dir, "02_Acct_會計模組.epub"),
            'title_zh': "會計模組操作說明",
            'title_en': "Accounting Module"
        },
        {
            'extract': r"C:\temp\chm_stock",
            'output': os.path.join(output_dir, "03_Stock_庫存模組.epub"),
            'title_zh': "庫存模組操作說明",
            'title_en': "Stock Module"
        },
        {
            'extract': r"C:\temp\chm_salary",
            'output': os.path.join(output_dir, "04_Salary_薪資模組.epub"),
            'title_zh': "薪資模組操作說明",
            'title_en': "Salary Module"
        },
        {
            'extract': r"C:\temp\chm_prod",
            'output': os.path.join(output_dir, "05_Prod_生產模組.epub"),
            'title_zh': "生產模組操作說明",
            'title_en': "Production Module"
        },
    ]

    print("\n" + "=" * 60)
    print("CHM 轉 EPUB 電子書")
    print("=" * 60)

    results = []
    for item in chm_list:
        if os.path.exists(item['extract']):
            ok = generate_epub(
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
