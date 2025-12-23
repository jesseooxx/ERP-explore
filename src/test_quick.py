#!/usr/bin/env python3
"""
快速測試 - 繞過 __init__.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

# 直接導入，不通過 __init__
import datawin_renderer.fast_parser as fast_parser
import datawin_renderer.fast_renderer as fast_renderer
import datawin_renderer.parser as parser
import datawin_renderer.renderer as renderer

import time
import os

def main():
    print("=" * 70)
    print("SAMPLE_REPORT.TMP 快速測試")
    print("=" * 70)

    template = "nrp_backup/sample_report.tmp"
    output_fast = "output/quick_test_fast.pdf"
    output_orig = "output/quick_test_orig.pdf"

    os.makedirs("output", exist_ok=True)

    # 測試 1: 快速解析
    print("\n[1] 快速解析")
    start = time.perf_counter()
    fparser = fast_parser.FastReportParser(template)
    doc = fparser.parse()
    parse_time = time.perf_counter() - start
    print(f"  OK {parse_time*1000:.2f}ms")
    print(f"  標題: {doc.title}")
    print(f"  元素: {len(doc.elements)}")

    # 測試 2: 快速渲染
    print("\n[2] 快速渲染")
    start = time.perf_counter()
    frenderer = fast_renderer.FastPDFRenderer(enable_cache=True)
    frenderer.render(doc, output_fast)
    render_fast_time = time.perf_counter() - start
    print(f"  OK {render_fast_time*1000:.2f}ms")
    print(f"  輸出: {output_fast}")
    if os.path.exists(output_fast):
        print(f"  大小: {os.path.getsize(output_fast)/1024:.1f} KB")

    # 測試 3: 原始渲染（比較）
    print("\n[3] 原始渲染")
    start = time.perf_counter()
    oparser = parser.ReportParser(template)
    doc2 = oparser.parse()
    orenderer = renderer.PDFRenderer()
    orenderer.render(doc2, output_orig)
    render_orig_time = time.perf_counter() - start
    print(f"  OK {render_orig_time*1000:.2f}ms")
    print(f"  輸出: {output_orig}")
    if os.path.exists(output_orig):
        print(f"  大小: {os.path.getsize(output_orig)/1024:.1f} KB")

    # 與原始 PDF 比較
    print("\n[4] 與原始 ERP PDF 比較")
    original_pdf = "nrp_backup/sample_PI.pdf"
    if os.path.exists(original_pdf):
        orig_size = os.path.getsize(original_pdf)
        fast_size = os.path.getsize(output_fast)
        print(f"  原始 ERP: {orig_size/1024:.1f} KB")
        print(f"  快速生成: {fast_size/1024:.1f} KB")
        print(f"  差異: {abs(orig_size-fast_size)/orig_size*100:.1f}%")
    else:
        print(f"  ⚠️ 原始 PDF 不存在")

    # 總結
    print("\n" + "=" * 70)
    print("性能總結")
    print("=" * 70)
    speedup = render_orig_time / render_fast_time
    print(f"  快速渲染: {render_fast_time*1000:.2f}ms")
    print(f"  原始渲染: {render_orig_time*1000:.2f}ms")
    print(f"  加速比: {speedup:.2f}x")

    print(f"\n✅ 測試完成！")
    print(f"\n📁 請打開以下文件進行視覺比較:")
    print(f"  1. {original_pdf} (原始 ERP)")
    print(f"  2. {output_fast} (快速渲染)")
    print(f"  3. {output_orig} (原始渲染)")

if __name__ == "__main__":
    main()
