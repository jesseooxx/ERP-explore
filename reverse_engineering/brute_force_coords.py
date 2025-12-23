"""
暴力破解座標轉換公式
嘗試所有可能的組合，找到最匹配原始 PDF 的方案
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import PyPDF2
import os
from typing import Tuple

class BruteForceRenderer:
    """暴力測試渲染器"""

    def __init__(self, scale_x: float, scale_y: float, origin_mode: str = 'top-left'):
        """
        origin_mode:
          'top-left': (0,0) 在左上
          'bottom-left': (0,0) 在左下
        """
        self.scale_x = scale_x
        self.scale_y = scale_y
        self.origin_mode = origin_mode
        self.page_width, self.page_height = A4

    def render_test(self, output_path: str):
        """渲染測試模式 - 簡單的幾何圖形和文字"""

        c = canvas.Canvas(output_path, pagesize=A4)
        c.setTitle(f"Test sx={self.scale_x:.3f} sy={self.scale_y:.3f} mode={self.origin_mode}")

        # 繪製參考網格
        c.setStrokeColor(colors.lightgrey)
        c.setLineWidth(0.5)

        # 垂直線
        for x in range(0, 900, 100):
            px = x * self.scale_x
            c.line(px, 0, px, self.page_height)

        # 水平線
        for y in range(0, 1200, 100):
            py = self._convert_y(y)
            c.line(0, py, self.page_width, py)

        # 繪製測試元素（模擬模板中的實際元素）
        # 基於模板分析：
        # - LABEL "PAGE : " @ (0, 0, 42, 15)
        # - EDIT @ (42, 0, 24, 15)

        c.setStrokeColor(colors.black)
        c.setFont("Helvetica", 12)

        # 測試點 1: (0, 0) 應該在哪裡？
        self._draw_test_label(c, "ORIGIN (0,0)", 0, 0)

        # 測試點 2: (100, 0)
        self._draw_test_label(c, "(100,0)", 100, 0)

        # 測試點 3: (0, 100)
        self._draw_test_label(c, "(0,100)", 0, 100)

        # 測試點 4: (100, 100)
        self._draw_test_label(c, "(100,100)", 100, 100)

        # 測試模板實際值: "PAGE : " 標籤
        # 在 PLANK ID=1 @ (0, 0) 內的 LABEL @ (0, 0, 42, 15)
        self._draw_test_label(c, "PAGE :", 0, 0)

        # 右邊的日期區域: PLANK ID=4 @ (460, 0)
        self._draw_test_label(c, "Date:", 460, 0)

        c.showPage()
        c.save()

    def _convert_y(self, y: int) -> float:
        """Y 座標轉換"""
        if self.origin_mode == 'top-left':
            # 模板 Y 向下增加，PDF Y 向上增加，需要翻轉
            return self.page_height - (y * self.scale_y)
        else:
            # PDF 原生座標（左下原點）
            return y * self.scale_y

    def _draw_test_label(self, c, text: str, x: int, y: int):
        """繪製測試標籤"""
        px = x * self.scale_x
        py = self._convert_y(y)

        # 繪製標記點
        c.setFillColor(colors.red)
        c.circle(px, py, 2, fill=1)

        # 繪製文字
        c.setFillColor(colors.black)
        c.drawString(px + 5, py, text)


def generate_test_matrix():
    """生成測試矩陣"""

    print("=" * 70)
    print("暴力測試座標轉換")
    print("=" * 70)

    os.makedirs("output/brute_force", exist_ok=True)

    # 測試組合
    test_cases = [
        # (scale_x, scale_y, origin_mode, description)
        (1.0, 1.0, 'top-left', "1:1 上左原點"),
        (0.283, 0.283, 'top-left', "0.1mm 上左原點"),
        (0.661, 0.702, 'top-left', "A4縮放 上左原點"),
        (595/900, 842/1200, 'top-left', "頁面比例 上左原點"),

        (1.0, 1.0, 'bottom-left', "1:1 下左原點"),
        (0.283, 0.283, 'bottom-left', "0.1mm 下左原點"),

        # 基於發現的常量推測
        (72/254, 72/254, 'top-left', "DPI/mm 轉換"),
        (595/900, 595/900, 'top-left', "等比例縮放"),

        # 嘗試不縮放
        (1.0, -1.0, 'bottom-left', "Y軸反轉"),
    ]

    results = []

    for idx, (sx, sy, mode, desc) in enumerate(test_cases):
        output = f"output/brute_force/test_{idx:02d}_{desc.replace(' ', '_')}.pdf"

        print(f"\n[{idx+1}/{len(test_cases)}] 測試: {desc}")
        print(f"  scale_x={sx:.4f}, scale_y={sy:.4f}, mode={mode}")

        try:
            renderer = BruteForceRenderer(sx, sy, mode)
            renderer.render_test(output)
            print(f"  生成: {output}")

            results.append({
                'index': idx,
                'scale_x': sx,
                'scale_y': sy,
                'mode': mode,
                'desc': desc,
                'output': output,
                'success': True
            })

        except Exception as e:
            print(f"  錯誤: {e}")
            results.append({
                'index': idx,
                'success': False,
                'error': str(e)
            })

    # 保存結果
    print("\n" + "=" * 70)
    print("測試完成")
    print("=" * 70)
    print(f"\n生成了 {len([r for r in results if r['success']])} 個測試 PDF")
    print("\n請打開 output/brute_force/ 目錄")
    print("找到最接近原始 PDF 的版本")
    print("然後告訴我是哪一個 (test_XX)")

    return results


if __name__ == "__main__":
    results = generate_test_matrix()
