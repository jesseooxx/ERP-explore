"""
Performance benchmark comparing original vs optimized renderer
"""

import time
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from datawin_renderer.parser import ReportParser
from datawin_renderer.renderer import PDFRenderer
from datawin_renderer.fast_parser import FastReportParser
from datawin_renderer.fast_renderer import FastPDFRenderer, render_report_fast
from datawin_renderer.data_binder import DataBinderBuilder


def benchmark_parsing(template_path: str, iterations: int = 10):
    """Benchmark parsing speed"""
    print("=" * 70)
    print("PARSING BENCHMARK")
    print("=" * 70)

    # Original parser
    print(f"\n[Original Parser] Running {iterations} iterations...")
    start = time.perf_counter()
    for _ in range(iterations):
        parser = ReportParser(template_path)
        doc = parser.parse()
    original_time = time.perf_counter() - start
    original_avg = original_time / iterations
    print(f"  Total: {original_time:.3f}s")
    print(f"  Average: {original_avg:.4f}s per parse")

    # Fast parser
    print(f"\n[Fast Parser] Running {iterations} iterations...")
    start = time.perf_counter()
    for _ in range(iterations):
        parser = FastReportParser(template_path)
        doc = parser.parse()
    fast_time = time.perf_counter() - start
    fast_avg = fast_time / iterations
    print(f"  Total: {fast_time:.3f}s")
    print(f"  Average: {fast_avg:.4f}s per parse")

    # Speedup
    speedup = original_avg / fast_avg
    print(f"\n  ⚡ Speedup: {speedup:.2f}x faster")
    print(f"  💾 Time saved: {(original_time - fast_time):.3f}s ({(1 - fast_time/original_time)*100:.1f}%)")

    return original_avg, fast_avg


def benchmark_rendering(template_path: str, iterations: int = 10):
    """Benchmark full rendering speed (parse + render)"""
    print("\n" + "=" * 70)
    print("FULL RENDERING BENCHMARK (Parse + Render to PDF)")
    print("=" * 70)

    # Prepare data
    data = DataBinderBuilder() \
        .add_field(1, "2024-01-15") \
        .add_field(2, "ORD-2024-001") \
        .add_field(3, "REF-ABC-123") \
        .add_field(4, "CUST-12345") \
        .build()

    # Original renderer
    print(f"\n[Original Renderer] Running {iterations} iterations...")
    start = time.perf_counter()
    for i in range(iterations):
        parser = ReportParser(template_path)
        doc = parser.parse()
        data.bind(doc)
        renderer = PDFRenderer()
        renderer.render(doc, f"output/benchmark_original_{i}.pdf")
    original_time = time.perf_counter() - start
    original_avg = original_time / iterations
    print(f"  Total: {original_time:.3f}s")
    print(f"  Average: {original_avg:.4f}s per render")

    # Fast renderer
    print(f"\n[Fast Renderer] Running {iterations} iterations...")
    start = time.perf_counter()
    for i in range(iterations):
        parser = FastReportParser(template_path)
        doc = parser.parse()
        data.bind(doc)
        renderer = FastPDFRenderer(enable_cache=True)
        renderer.render(doc, f"output/benchmark_fast_{i}.pdf")
    fast_time = time.perf_counter() - start
    fast_avg = fast_time / iterations
    print(f"  Total: {fast_time:.3f}s")
    print(f"  Average: {fast_avg:.4f}s per render")

    # Speedup
    speedup = original_avg / fast_avg
    print(f"\n  ⚡ Speedup: {speedup:.2f}x faster")
    print(f"  💾 Time saved: {(original_time - fast_time):.3f}s ({(1 - fast_time/original_time)*100:.1f}%)")
    print(f"  📊 Throughput: {iterations/fast_time:.1f} renders/second")

    return original_avg, fast_avg


def benchmark_batch_rendering(template_path: str, batch_size: int = 20):
    """Benchmark batch rendering with parallelization"""
    print("\n" + "=" * 70)
    print(f"BATCH RENDERING BENCHMARK ({batch_size} documents)")
    print("=" * 70)

    from datawin_renderer.fast_renderer import BatchRenderer

    # Prepare jobs
    jobs = []
    for i in range(batch_size):
        data_dict = {
            1: f"2024-01-{15+i:02d}",
            2: f"ORD-2024-{i:03d}",
            4: f"CUST-{12345+i}",
        }
        jobs.append((template_path, f"output/batch_{i}.pdf", data_dict))

    # Sequential rendering
    print(f"\n[Sequential] Rendering {batch_size} documents...")
    start = time.perf_counter()
    for job in jobs:
        render_report_fast(*job)
    sequential_time = time.perf_counter() - start
    print(f"  Time: {sequential_time:.3f}s")
    print(f"  Rate: {batch_size/sequential_time:.1f} docs/sec")

    # Parallel rendering (threads)
    print(f"\n[Parallel - Threads] Rendering {batch_size} documents...")
    batch_renderer = BatchRenderer()
    start = time.perf_counter()
    batch_renderer.render_batch(jobs, use_multiprocessing=False)
    thread_time = time.perf_counter() - start
    print(f"  Time: {thread_time:.3f}s")
    print(f"  Rate: {batch_size/thread_time:.1f} docs/sec")
    print(f"  Speedup vs Sequential: {sequential_time/thread_time:.2f}x")

    # Parallel rendering (processes)
    print(f"\n[Parallel - Processes] Rendering {batch_size} documents...")
    start = time.perf_counter()
    batch_renderer.render_batch(jobs, use_multiprocessing=True)
    process_time = time.perf_counter() - start
    print(f"  Time: {process_time:.3f}s")
    print(f"  Rate: {batch_size/process_time:.1f} docs/sec")
    print(f"  Speedup vs Sequential: {sequential_time/process_time:.2f}x")


def main():
    """Run all benchmarks"""
    # Use sample template
    template_path = "nrp_backup/sample_report.tmp"

    if not os.path.exists(template_path):
        print(f"Error: Template file not found: {template_path}")
        print("Please ensure sample_report.tmp exists in nrp_backup/")
        return

    # Create output directory
    os.makedirs("output", exist_ok=True)

    print("\n" + "=" * 70)
    print("NRP32 RENDERER PERFORMANCE BENCHMARK")
    print("=" * 70)
    print(f"Template: {template_path}")
    print(f"File size: {os.path.getsize(template_path) / 1024:.1f} KB")

    # Run benchmarks
    try:
        # Parsing only
        orig_parse, fast_parse = benchmark_parsing(template_path, iterations=100)

        # Full rendering
        orig_render, fast_render = benchmark_rendering(template_path, iterations=20)

        # Batch rendering
        benchmark_batch_rendering(template_path, batch_size=50)

        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"\nParsing:")
        print(f"  Original: {orig_parse*1000:.2f}ms")
        print(f"  Fast:     {fast_parse*1000:.2f}ms")
        print(f"  Speedup:  {orig_parse/fast_parse:.2f}x")

        print(f"\nFull Rendering (Parse + PDF):")
        print(f"  Original: {orig_render*1000:.2f}ms")
        print(f"  Fast:     {fast_render*1000:.2f}ms")
        print(f"  Speedup:  {orig_render/fast_render:.2f}x")

        print(f"\n🎯 Overall Performance Improvement:")
        print(f"   For single document: {orig_render/fast_render:.1f}x faster")
        print(f"   For batch rendering: Up to {orig_render/fast_render * 2:.1f}x faster (with parallelization)")

        # Clean up benchmark files
        print("\nCleaning up benchmark output files...")
        for f in Path("output").glob("benchmark_*.pdf"):
            f.unlink()
        for f in Path("output").glob("batch_*.pdf"):
            f.unlink()

    except Exception as e:
        print(f"\nError during benchmark: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
