"""
暴力測試 - 使用真實模板數據
找到正確的座標轉換
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from datawin_renderer.fast_parser import FastReportParser
from datawin_renderer.data_binder import DataBinderBuilder
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import PyPDF2
import os
import time

class TestRenderer:
    """測試渲染器 - 可配置座標轉換"""

    def __init__(self, scale_x: float, scale_y: float, y_mode: str = 'flip'):
        self.scale_x = scale_x
        self.scale_y = scale_y
        self.y_mode = y_mode  # 'flip' or 'direct'
        self.page_width, self.page_height = A4

    def render_simple(self, document, output_path: str):
        """簡化渲染 - 只渲染主要文字"""

        c = canvas.Canvas(output_path, pagesize=A4, pageCompression=1)
        c.setTitle(document.title)

        # 只渲染前 50 個元素進行快速測試
        count = 0

        for elem in document.elements:
            if not hasattr(elem, 'children'):
                continue

            # 這是 PLANK
            plank_x = elem.x * self.scale_x
            plank_y = elem.y * self.scale_y

            for child in elem.children:
                if count >= 50:  # 限制元素數量
                    break

                if child.element_type == 'LABEL':
                    # 繪製 LABEL
                    x = plank_x + (child.x * self.scale_x)
                    y = self._convert_y(plank_y + (child.y * self.scale_y))

                    c.setFont("Helvetica", 10)
                    c.drawString(x, y, child.text)
                    count += 1

                elif child.element_type == 'EDIT' and child.bound_data:
                    # 繪製有數據的 EDIT
                    x = plank_x + (child.x * self.scale_x)
                    y = self._convert_y(plank_y + (child.y * self.scale_y))

                    c.setFont("Helvetica-Bold", 10)
                    c.drawString(x, y, child.bound_data)
                    count += 1

        # 繪製參考標記
        c.setFillColor(colors.red)
        c.circle(10, self.page_height - 10, 3, fill=1)
        c.drawString(15, self.page_height - 15, f"sx={self.scale_x:.3f} sy={self.scale_y:.3f}")

        c.showPage()
        c.save()

    def _convert_y(self, y: float) -> float:
        """Y 座標轉換"""
        if self.y_mode == 'flip':
            return self.page_height - y
        else:
            return y


def run_brute_force_tests():
    """運行暴力測試"""

    print("=" * 70)
    print("暴力測試真實模板")
    print("=" * 70)

    # 解析真實模板
    template = "nrp_backup/sample_report.tmp"
    parser = FastReportParser(template)
    doc = parser.parse()

    # 綁定測試數據
    binder = DataBinderBuilder()
    binder.add_field(1, "DEC. 23, 2025")
    binder.add_field(2, "506046")
    binder.add_field(3, "T25C22")
    binder.add_field(4, "604")
    data = binder.build()
    data.bind(doc)

    os.makedirs("output/brute_force_real", exist_ok=True)

    # 測試不同的縮放因子
    test_cases = [
        # (scale_x, scale_y, y_mode, description)
        (1.0, 1.0, 'flip', "無縮放-翻轉Y"),
        (0.5, 0.5, 'flip', "0.5倍-翻轉Y"),
        (0.66, 0.70, 'flip', "A4比例-翻轉Y"),
        (0.283, 0.283, 'flip', "0.1mm-翻轉Y"),

        # 嘗試不同的 Y 處理
        (0.66, 0.70, 'direct', "A4比例-直接Y"),

        # 基於找到的常量
        (595/900, 842/1200, 'flip', "頁面比例-翻轉Y"),

        # 極端情況
        (2.0, 2.0, 'flip', "2倍-翻轉Y"),
        (0.1, 0.1, 'flip', "0.1倍-翻轉Y"),
    ]

    results = []

    for idx, (sx, sy, ymode, desc) in enumerate(test_cases):
        output = f"output/brute_force_real/test_{idx:02d}_{desc}.pdf"

        print(f"\n[{idx+1}/{len(test_cases)}] {desc}")
        print(f"  sx={sx:.4f}, sy={sy:.4f}, ymode={ymode}")

        try:
            renderer = TestRenderer(sx, sy, ymode)
            start = time.perf_counter()
            renderer.render_simple(doc, output)
            elapsed = time.perf_counter() - start

            # 檢查結果
            size = os.path.getsize(output)
            print(f"  生成: {output} ({size/1024:.1f} KB, {elapsed*1000:.0f}ms)")

            results.append({
                'index': idx,
                'desc': desc,
                'scale_x': sx,
                'scale_y': sy,
                'y_mode': ymode,
                'output': output,
                'size': size,
                'time': elapsed
            })

        except Exception as e:
            print(f"  錯誤: {e}")

    # 生成對照表
    print("\n" + "=" * 70)
    print("測試結果匯總")
    print("=" * 70)

    print(f"\n{'#':<3} {'描述':<20} {'縮放':<15} {'文件':<10}")
    print("-" * 70)
    for r in results:
        print(f"{r['index']:<3} {r['desc']:<20} {r['scale_x']:.3f}x{r['scale_y']:.3f}  {r['size']/1024:>6.1f} KB")

    print("\n" + "=" * 70)
    print("下一步")
    print("=" * 70)
    print("\n1. 打開 output/brute_force_real/ 目錄")
    print("2. 對比每個 PDF 與原始 nrp_backup/sample_PI.pdf")
    print("3. 找到位置最接近的版本")
    print("4. 告訴我是 test_XX")
    print("\n提示: 看 'PAGE :' 和 'Date:' 的位置是否正確")


if __name__ == "__main__":
    run_brute_force_tests()
