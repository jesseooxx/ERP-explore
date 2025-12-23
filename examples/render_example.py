"""
Example: Render Datawin Report to PDF with data binding
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.datawin_renderer import ReportParser, PDFRenderer, DataBinder, DataBinderBuilder


def example1_simple_render():
    """Example 1: Simple rendering without data binding"""
    print("=" * 60)
    print("Example 1: Simple Rendering (No Data Binding)")
    print("=" * 60)

    template_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"
    output_path = r"C:\真桌面\Claude code\ERP explore\output\example1_simple.pdf"

    # Parse template
    parser = ReportParser(template_path)
    document = parser.parse()

    print(f"Parsed document: {document.title}")
    print(f"Total elements: {len(document.elements)}")
    print(f"PLANKs: {len(document.get_planks())}")

    # Render to PDF
    renderer = PDFRenderer()
    renderer.render(document, output_path)

    print(f"\n✓ PDF generated: {output_path}\n")


def example2_with_data_binding():
    """Example 2: Rendering with data binding"""
    print("=" * 60)
    print("Example 2: Rendering with Data Binding")
    print("=" * 60)

    template_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"
    output_path = r"C:\真桌面\Claude code\ERP explore\output\example2_with_data.pdf"

    # Parse template
    parser = ReportParser(template_path)
    document = parser.parse()

    # Create data binder with invoice data
    binder = (DataBinderBuilder()
              .add_field(0, "PROFORMA INVOICE")
              .add_field(1, "2024-12-23")
              .add_field(2, "ORD-2024-1223-001")
              .add_field(3, "REF-ABC-XYZ-2024")
              .add_field(4, "CUST-98765")
              .add_field(5, "+886-2-2345-6789")
              .add_field(6, "+886-2-2345-6790")
              .add_field(7, "2025-01-15")
              .add_field(99, "Rendered by Python Datawin Renderer")
              .build())

    print(f"Created data binder with {len(binder.data_source)} fields")

    # Validate data binding
    validation = binder.validate(document)
    print(f"Validation: {'✓ PASSED' if validation['valid'] else '✗ FAILED'}")
    print(f"  Bound fields: {validation['bound_edits']}/{validation['total_edits']}")
    if validation['missing_fields']:
        print(f"  Missing field IDs: {validation['missing_fields'][:10]}")

    # Bind data to document
    binder.bind(document)
    print("Data bound to document")

    # Render to PDF
    renderer = PDFRenderer()
    renderer.render(document, output_path)

    print(f"\n✓ PDF generated: {output_path}\n")


def example3_from_json():
    """Example 3: Load data from JSON file"""
    print("=" * 60)
    print("Example 3: Data Binding from JSON")
    print("=" * 60)

    # Create sample JSON data file
    import json
    json_path = r"C:\真桌面\Claude code\ERP explore\output\sample_data.json"
    sample_data = {
        "0": "PROFORMA INVOICE",
        "1": "2024-12-23",
        "2": "ORD-JSON-12345",
        "3": "REF-JSON-99999",
        "4": "CUST-JSON-001",
        "5": "+1-555-0100",
        "6": "+1-555-0101",
        "7": "2025-02-01"
    }

    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(sample_data, f, indent=2, ensure_ascii=False)

    print(f"Created sample JSON: {json_path}")

    # Load and render
    template_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"
    output_path = r"C:\真桌面\Claude code\ERP explore\output\example3_from_json.pdf"

    parser = ReportParser(template_path)
    document = parser.parse()

    # Load data from JSON
    binder = DataBinder.from_json(json_path)
    binder.bind(document)

    print(f"Loaded {len(binder.data_source)} fields from JSON")

    # Render
    renderer = PDFRenderer()
    renderer.render(document, output_path)

    print(f"\n✓ PDF generated: {output_path}\n")


def example4_convenience_function():
    """Example 4: Using convenience function"""
    print("=" * 60)
    print("Example 4: One-Line Rendering")
    print("=" * 60)

    from src.datawin_renderer.renderer import render_report

    template_path = r"C:\真桌面\Claude code\ERP explore\nrp_backup\sample_report.tmp"
    output_path = r"C:\真桌面\Claude code\ERP explore\output\example4_oneline.pdf"

    # One-line render
    render_report(
        template_path,
        output_path,
        data_dict={
            1: "2024-12-23",
            2: "ORD-QUICK-999",
            3: "REF-QUICK",
            4: "CUST-QUICK-123",
            5: "+886-2-9999-8888",
            6: "+886-2-9999-8889",
        }
    )

    print(f"\n✓ PDF generated: {output_path}\n")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("Datawin Report Renderer - Examples")
    print("=" * 60 + "\n")

    # Create output directory
    os.makedirs(r"C:\真桌面\Claude code\ERP explore\output", exist_ok=True)

    try:
        example1_simple_render()
        example2_with_data_binding()
        example3_from_json()
        example4_convenience_function()

        print("\n" + "=" * 60)
        print("✓ All examples completed successfully!")
        print("=" * 60)
        print("\nGenerated PDFs:")
        print("  - output/example1_simple.pdf")
        print("  - output/example2_with_data.pdf")
        print("  - output/example3_from_json.pdf")
        print("  - output/example4_oneline.pdf")
        print("\n")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
