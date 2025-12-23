#!/usr/bin/env python3
"""
測試 sample_report.tmp - 與原始 PDF 比對
"""

import sys
import os
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from datawin_renderer.fast_parser import FastReportParser
from datawin_renderer.fast_renderer import FastPDFRenderer, render_report_fast
from datawin_renderer.parser import ReportParser
from datawin_renderer.renderer import PDFRenderer


def test_parse():
    """測試解析"""
    print("=" * 70)
    print("步驟 1: 解析模板文件")
    print("=" * 70)

    template = "nrp_backup/sample_report.tmp"

    print(f"\n模板文件: {template}")
    file_size = os.path.getsize(template)
    print(f"文件大小: {file_size} bytes ({file_size/1024:.2f} KB)")

    # 快速解析
    print(f"\n[快速解析器] 解析中...")
    start = time.perf_counter()
    parser = FastReportParser(template)
    doc = parser.parse()
    parse_time = time.perf_counter() - start

    print(f"✅ 解析完成 ({parse_time*1000:.2f}ms)")
    print(f"\n📋 解析結果:")
    print(f"  標題: {doc.title}")
    print(f"  Magic: {doc.magic}")
    print(f"  版本: {doc.version_info.get('version', 'N/A')}")
    print(f"  PLANK 數量: {doc.version_info.get('plank_count', 'N/A')}")
    print(f"  元素總數: {doc.version_info.get('element_count', 'N/A')}")

    # 統計元素
    from collections import Counter
    types = Counter()

    for elem in doc.elements:
        types[elem.element_type] += 1
        if hasattr(elem, 'children'):
            for child in elem.children:
                types[child.element_type] += 1

    print(f"\n📊 元素統計:")
    for etype, count in sorted(types.items()):
        print(f"  {etype:10s}: {count:3d}")

    # 顯示一些樣本元素
    print(f"\n🔍 樣本 LABEL 元素 (前 10 個):")
    label_count = 0
    for elem in doc.elements:
        if hasattr(elem, 'children'):
            for child in elem.children:
                if child.element_type == 'LABEL' and label_count < 10:
                    print(f"  - \"{child.text}\" @ ({child.x}, {child.y})")
                    label_count += 1

    return doc, parse_time


def test_render_fast(doc):
    """使用快速渲染器生成 PDF"""
    print("\n" + "=" * 70)
    print("步驟 2: 使用快速渲染器生成 PDF")
    print("=" * 70)

    output = "output/test_fast_render.pdf"
    os.makedirs("output", exist_ok=True)

    print(f"\n輸出文件: {output}")

    start = time.perf_counter()
    renderer = FastPDFRenderer(enable_cache=True)
    renderer.render(doc, output)
    render_time = time.perf_counter() - start

    print(f"✅ 渲染完成 ({render_time*1000:.2f}ms)")

    if os.path.exists(output):
        size = os.path.getsize(output)
        print(f"📄 PDF 大小: {size} bytes ({size/1024:.2f} KB)")

    return output, render_time


def test_render_original(doc):
    """使用原始渲染器生成 PDF（用於比較）"""
    print("\n" + "=" * 70)
    print("步驟 3: 使用原始渲染器生成 PDF（比較基準）")
    print("=" * 70)

    output = "output/test_original_render.pdf"

    print(f"\n輸出文件: {output}")

    start = time.perf_counter()
    renderer = PDFRenderer()
    renderer.render(doc, output)
    render_time = time.perf_counter() - start

    print(f"✅ 渲染完成 ({render_time*1000:.2f}ms)")

    if os.path.exists(output):
        size = os.path.getsize(output)
        print(f"📄 PDF 大小: {size} bytes ({size/1024:.2f} KB)")

    return output, render_time


def compare_with_original():
    """與原始 ERP 輸出比較"""
    print("\n" + "=" * 70)
    print("步驟 4: 與原始 ERP PDF 比較")
    print("=" * 70)

    original_pdf = "nrp_backup/sample_PI.pdf"
    fast_pdf = "output/test_fast_render.pdf"

    if not os.path.exists(original_pdf):
        print(f"⚠️  原始 PDF 不存在: {original_pdf}")
        return

    orig_size = os.path.getsize(original_pdf)
    fast_size = os.path.getsize(fast_pdf)

    print(f"\n📊 文件大小比較:")
    print(f"  原始 ERP PDF:  {orig_size:8d} bytes ({orig_size/1024:.2f} KB)")
    print(f"  快速渲染 PDF:  {fast_size:8d} bytes ({fast_size/1024:.2f} KB)")
    print(f"  大小差異:      {abs(orig_size-fast_size):8d} bytes ({abs(orig_size-fast_size)/orig_size*100:.1f}%)")

    # 嘗試使用 PyPDF2 進行更詳細的比較
    try:
        from PyPDF2 import PdfReader

        print(f"\n📑 PDF 內容分析:")

        orig_pdf_obj = PdfReader(original_pdf)
        fast_pdf_obj = PdfReader(fast_pdf)

        print(f"  原始 PDF 頁數: {len(orig_pdf_obj.pages)}")
        print(f"  生成 PDF 頁數: {len(fast_pdf_obj.pages)}")

        # 提取第一頁文字
        orig_text = orig_pdf_obj.pages[0].extract_text()
        fast_text = fast_pdf_obj.pages[0].extract_text()

        print(f"\n  原始 PDF 文字長度: {len(orig_text)} chars")
        print(f"  生成 PDF 文字長度: {len(fast_text)} chars")

        # 檢查關鍵文字
        key_texts = ["PROFORMA INVOICE", "Messrs", "Date", "ORDER"]
        print(f"\n  關鍵文字檢查:")
        for text in key_texts:
            in_orig = text in orig_text
            in_fast = text in fast_text
            status = "✅" if (in_orig == in_fast) else "❌"
            print(f"    {status} '{text}': 原始={in_orig}, 生成={in_fast}")

    except ImportError:
        print(f"\n💡 提示: 安裝 PyPDF2 可進行更詳細的比較")
        print(f"   pip install PyPDF2")
    except Exception as e:
        print(f"\n⚠️  PDF 比較錯誤: {e}")


def visual_comparison():
    """視覺比較指南"""
    print("\n" + "=" * 70)
    print("步驟 5: 視覺比較")
    print("=" * 70)

    print(f"\n📖 請手動打開以下文件進行視覺比較:")
    print(f"\n  1. 原始 ERP 輸出:")
    print(f"     nrp_backup/sample_PI.pdf")
    print(f"\n  2. 快速渲染輸出:")
    print(f"     output/test_fast_render.pdf")
    print(f"\n  3. 原始渲染輸出:")
    print(f"     output/test_original_render.pdf")

    print(f"\n🔍 檢查項目:")
    print(f"  ✓ 標題位置和樣式")
    print(f"  ✓ 文字對齊 (左/右/中)")
    print(f"  ✓ 線條位置")
    print(f"  ✓ 字體大小")
    print(f"  ✓ 整體佈局")


def benchmark():
    """性能測試"""
    print("\n" + "=" * 70)
    print("步驟 6: 性能基準測試")
    print("=" * 70)

    template = "nrp_backup/sample_report.tmp"
    iterations = 20

    print(f"\n🏃 運行 {iterations} 次渲染...")

    # 快速版本
    print(f"\n[快速渲染器]")
    times = []
    for i in range(iterations):
        parser = FastReportParser(template)
        doc = parser.parse()

        start = time.perf_counter()
        renderer = FastPDFRenderer(enable_cache=True)
        renderer.render(doc, f"output/bench_fast_{i}.pdf")
        times.append(time.perf_counter() - start)

    fast_avg = sum(times) / len(times)
    fast_min = min(times)
    fast_max = max(times)

    print(f"  平均: {fast_avg*1000:.2f}ms")
    print(f"  最快: {fast_min*1000:.2f}ms")
    print(f"  最慢: {fast_max*1000:.2f}ms")

    # 原始版本
    print(f"\n[原始渲染器]")
    times = []
    for i in range(iterations):
        parser = ReportParser(template)
        doc = parser.parse()

        start = time.perf_counter()
        renderer = PDFRenderer()
        renderer.render(doc, f"output/bench_orig_{i}.pdf")
        times.append(time.perf_counter() - start)

    orig_avg = sum(times) / len(times)
    orig_min = min(times)
    orig_max = max(times)

    print(f"  平均: {orig_avg*1000:.2f}ms")
    print(f"  最快: {orig_min*1000:.2f}ms")
    print(f"  最慢: {orig_max*1000:.2f}ms")

    speedup = orig_avg / fast_avg
    print(f"\n⚡ 加速比: {speedup:.2f}x")

    # 清理基準測試文件
    print(f"\n🧹 清理基準測試文件...")
    for i in range(iterations):
        for prefix in ['bench_fast_', 'bench_orig_']:
            f = Path(f"output/{prefix}{i}.pdf")
            if f.exists():
                f.unlink()


def main():
    """主測試流程"""
    print("\n" + "=" * 70)
    print("SAMPLE_REPORT.TMP 完整測試")
    print("=" * 70)
    print("\n測試內容:")
    print("  1. 解析模板")
    print("  2. 快速渲染器生成 PDF")
    print("  3. 原始渲染器生成 PDF")
    print("  4. 與原始 ERP PDF 比較")
    print("  5. 視覺比較指南")
    print("  6. 性能基準測試")

    try:
        # 執行測試
        doc, parse_time = test_parse()
        fast_pdf, fast_time = test_render_fast(doc)
        orig_pdf, orig_time = test_render_original(doc)

        compare_with_original()
        visual_comparison()
        benchmark()

        # 總結
        print("\n" + "=" * 70)
        print("測試總結")
        print("=" * 70)

        print(f"\n⏱️  性能:")
        print(f"  解析時間: {parse_time*1000:.2f}ms")
        print(f"  快速渲染: {fast_time*1000:.2f}ms")
        print(f"  原始渲染: {orig_time*1000:.2f}ms")
        print(f"  加速比:   {orig_time/fast_time:.2f}x")

        print(f"\n✅ 測試完成!")
        print(f"\n📁 輸出文件:")
        print(f"  - output/test_fast_render.pdf     (快速渲染)")
        print(f"  - output/test_original_render.pdf (原始渲染)")

        print(f"\n💡 下一步:")
        print(f"  1. 打開 PDF 文件進行視覺比較")
        print(f"  2. 如有問題，檢查渲染差異")
        print(f"  3. 調整參數以匹配原始輸出")

    except Exception as e:
        print(f"\n❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
