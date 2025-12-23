"""
測試修正版渲染器
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import datawin_renderer.fast_parser as parser
import datawin_renderer.corrected_renderer as corrected
import datawin_renderer.data_binder as binder

import time
import os

def main():
    print("="*70)
    print("修正版渲染器測試")
    print("="*70)

    template = "nrp_backup/sample_report.tmp"
    output = "output/test_corrected.pdf"

    os.makedirs("output", exist_ok=True)

    # 解析模板
    print("\n[1] 解析模板...")
    start = time.perf_counter()
    p = parser.FastReportParser(template)
    doc = p.parse()
    parse_time = time.perf_counter() - start
    print(f"    完成: {parse_time*1000:.2f}ms")
    print(f"    元素: {len(doc.elements)}")

    # 綁定實際數據（從原始PDF手動提取）
    print("\n[2] 綁定數據...")
    test_data = {
        1: "DEC. 23, 2025",       # Date
        2: "506046",              # ORDER
        3: "T25C22",              # Ref
        4: "604",                 # Cust#
        5: "604 882 2026",        # Tel #
        6: "604 882 1494",        # Fax #
        7: "APR. 30, 2026",       # E.T.D.
        99: "MEGAPRO TOOLS INC.", # Special field
    }

    data_binder = binder.DataBinder.from_dict(test_data)
    data_binder.bind(doc)
    print(f"    綁定 {len(test_data)} 個字段")

    # 使用修正版渲染器
    print("\n[3] 渲染 PDF (修正版)...")
    start = time.perf_counter()
    renderer = corrected.CorrectedPDFRenderer()
    renderer.render(doc, output)
    render_time = time.perf_counter() - start
    print(f"    完成: {render_time*1000:.2f}ms")

    # 檢查結果
    if os.path.exists(output):
        size = os.path.getsize(output)
        print(f"\n[4] 結果")
        print(f"    文件: {output}")
        print(f"    大小: {size/1024:.1f} KB")

        # 與原始對比
        orig_size = os.path.getsize("nrp_backup/sample_PI.pdf")
        print(f"\n[5] 與原始對比")
        print(f"    原始 ERP: {orig_size/1024:.1f} KB")
        print(f"    修正版:   {size/1024:.1f} KB")
        print(f"    差異:     {abs(size-orig_size)/1024:.1f} KB ({abs(size-orig_size)/orig_size*100:.1f}%)")

        # 檢查頁數
        import PyPDF2
        with open(output, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            our_pages = len(pdf.pages)

        with open("nrp_backup/sample_PI.pdf", 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            orig_pages = len(pdf.pages)

        print(f"\n[6] 頁數對比")
        print(f"    原始 ERP: {orig_pages} 頁")
        print(f"    修正版:   {our_pages} 頁")
        if our_pages == orig_pages:
            print("    ✓ 頁數匹配!")
        else:
            print(f"    X 差異: {orig_pages - our_pages} 頁")

    print("\n"+"="*70)
    print("測試完成")
    print("="*70)
    print("\n請打開以下文件進行視覺對比:")
    print(f"  1. nrp_backup/sample_PI.pdf (原始)")
    print(f"  2. {output} (修正版)")

if __name__ == "__main__":
    main()
