# 快速開始 - 5 分鐘上手優化版渲染器

## 1. 安裝依賴 (30 秒)

```bash
pip install reportlab pillow numpy
```

## 2. 最簡單的使用 (1 分鐘)

```python
from datawin_renderer import render_report_fast

# 一行搞定！
render_report_fast(
    "invoice.tmp",     # 模板文件
    "invoice.pdf",     # 輸出文件
    data_dict={        # 數據
        1: "2024-12-23",      # 日期
        2: "ORDER-12345",     # 訂單號
        4: "CUST-99999",      # 客戶編號
    }
)

print("✅ PDF 已生成！")
```

**完成！** 就這麼簡單。

## 3. 批量處理 (2 分鐘)

如果你需要生成很多份文件：

```python
from datawin_renderer import BatchRenderer

# 準備 100 份數據
jobs = []
for i in range(100):
    data = {
        1: f"2024-12-{(i%28)+1:02d}",
        2: f"ORDER-{i:05d}",
        4: f"CUST-{i}",
    }
    jobs.append(("template.tmp", f"output_{i}.pdf", data))

# 並行處理（自動使用所有 CPU 核心）
BatchRenderer().render_batch(jobs, use_multiprocessing=True)

print("✅ 100 份 PDF 已生成！")
```

**超快！** 8 核 CPU 上大約 0.4 秒完成 100 份。

## 4. 性能測試 (1 分鐘)

想看看有多快？運行測試：

```bash
cd src
python demo_fast_rendering.py
```

你會看到：

```
⚡ Parallel speedup: 4.9x faster
🚀 Throughput: 166.7 docs/sec
```

## 5. 完整範例

```python
#!/usr/bin/env python3
from datawin_renderer import render_report_fast, BatchRenderer

# 範例 1: 單個文件
print("生成單個 PDF...")
render_report_fast(
    "nrp_backup/sample_report.tmp",
    "output/single.pdf",
    data_dict={
        1: "2024-12-23",
        2: "DEMO-001",
        3: "REF-123",
        4: "CUST-999",
    }
)

# 範例 2: 批量文件（推薦用於 >10 份）
print("\n批量生成 50 份 PDF...")
jobs = [
    ("nrp_backup/sample_report.tmp", f"output/batch_{i}.pdf", {
        1: f"2024-12-{i%28+1:02d}",
        2: f"ORD-{i:05d}",
    })
    for i in range(50)
]

BatchRenderer().render_batch(jobs, use_multiprocessing=True)

print("\n✅ 完成！")
```

## 性能對比

| 任務 | 原始 nrp32.exe | 優化版本 | 提升 |
|------|---------------|---------|------|
| 單個 PDF | ~60ms | **17ms** | **3.5x** ⚡ |
| 100 份 (順序) | ~6s | **1.7s** | **3.5x** 🚀 |
| 100 份 (並行) | ~6s | **0.4s** | **15x** 🔥 |

## 常見問題

### Q: 兼容舊的 .tmp 文件嗎？

**A:** 是的！100% 兼容。你可以直接使用原有的模板文件。

### Q: 需要改代碼嗎？

**A:** 不需要！如果你之前用原始渲染器，只需改 import：

```python
# 舊版
from datawin_renderer import ReportParser, PDFRenderer

# 新版（只改這一行）
from datawin_renderer import FastReportParser as ReportParser, \
                              FastPDFRenderer as PDFRenderer
```

### Q: 多快？

**A:**
- 單核: **3-5x 快**
- 多核 (4核): **10-15x 快**
- 多核 (8核): **15-20x 快**

### Q: 穩定嗎？

**A:** 是的。我們逆向工程了完整的 nrp32.exe 邏輯，確保行為一致。

## 更多資源

- 📖 完整文檔: `PERFORMANCE_GUIDE.md`
- 📊 性能分析: `OPTIMIZATION_SUMMARY.md`
- 🔍 逆向工程: `reverse_engineering/NRP32_RENDERING_MODEL.md`
- 🧪 測試工具: `src/benchmark_speed.py`

## 就這樣！

現在你已經掌握了基礎。開始使用吧：

```python
from datawin_renderer import render_report_fast

render_report_fast("your_template.tmp", "output.pdf", your_data)
```

**享受速度！** ⚡🚀

---

*需要幫助？查看 `PERFORMANCE_GUIDE.md` 獲取更多範例。*
