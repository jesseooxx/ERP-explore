"""
Query specific product details to confirm field mappings
"""

import pyodbc

def get_connection():
    conn_strings = [
        "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=DATAWIN;Trusted_Connection=yes;",
        "DRIVER={SQL Server};SERVER=localhost;DATABASE=DATAWIN;Trusted_Connection=yes;",
    ]
    for conn_str in conn_strings:
        try:
            return pyodbc.connect(conn_str, timeout=10)
        except:
            continue
    raise Exception("Could not connect to database")


def main():
    conn = get_connection()
    cursor = conn.cursor()

    print("=" * 80)
    print("Product Detail Query - Field Mapping Verification")
    print("=" * 80)

    # Try to find 284102 or similar products
    print("\n1. Searching for product 284102 or similar...")
    cursor.execute("SELECT da01, da02, da03, da04, da05, da06, da07, da08, da09, da10, da40, da41, da55, da56 FROM tdm01 WHERE da01 LIKE '284%' OR da01 LIKE '074%'")
    rows = cursor.fetchall()
    if rows:
        print(f"Found {len(rows)} products:")
        for row in rows:
            print(f"  ID={row.da01}, Name={row.da02}, Cat={row.da04}, Catalog={row.da05}")
            print(f"    NT$ Price(da08)={row.da08}, US$ Price(da10)={row.da10}")
            print(f"    Source(da40)={row.da40}, Supplier(da41)={row.da41}")
            print(f"    Created(da55)={row.da55} by {row.da56}")
    else:
        print("  284xxx/074xxx not found, showing sample products...")
        cursor.execute("SELECT TOP 5 da01, da02, da03, da04, da05, da06, da07, da08, da09, da10, da40, da41, da55, da56 FROM tdm01 WHERE da08 > 0")
        rows = cursor.fetchall()
        for row in rows:
            print(f"  ID={row.da01}, Name={row.da02}")
            print(f"    Cat(da04)={row.da04}, Catalog(da05)={row.da05}")
            print(f"    NT$ Curr(da07)={row.da07}, NT$ Price(da08)={row.da08}")
            print(f"    US$ Curr(da09)={row.da09}, US$ Price(da10)={row.da10}")
            print(f"    Source(da40)={row.da40}, Supplier(da41)={row.da41}")

    # Query all unique values for source type (da40) and da06
    print("\n2. Distinct values for key fields...")
    cursor.execute("SELECT DISTINCT da06, COUNT(*) as cnt FROM tdm01 GROUP BY da06 ORDER BY cnt DESC")
    print("  da06 values (product type?):")
    for row in cursor.fetchall():
        print(f"    {row.da06}: {row.cnt} products")

    cursor.execute("SELECT DISTINCT da40, COUNT(*) as cnt FROM tdm01 GROUP BY da40 ORDER BY cnt DESC")
    print("  da40 values (source type):")
    for row in cursor.fetchall():
        print(f"    {row.da40}: {row.cnt} products")

    # Query product description categories
    print("\n3. Product description categories (tdm02.db03)...")
    cursor.execute("SELECT DISTINCT db03, COUNT(*) as cnt FROM tdm02 GROUP BY db03 ORDER BY cnt DESC")
    for row in cursor.fetchall():
        print(f"  Category {row.db03}: {row.cnt} entries")

    # Query BOM structure
    print("\n4. BOM structure (tdm05) - sample data...")
    cursor.execute("""
        SELECT TOP 10 de01, de02, de03, de04, de05, de06, de09, de15, de18
        FROM tdm05
        WHERE de18 = 'Y'
        ORDER BY de01
    """)
    for row in cursor.fetchall():
        print(f"  Product={row.de01}, Component={row.de02}")
        print(f"    Ratio={row.de03}/{row.de04}, Supplier={row.de05}, Seq={row.de06}")
        print(f"    Main={row.de09}, Display={row.de15}, Active={row.de18}")

    # Query tcm05 supplier-product relationship
    print("\n5. Supplier-Product (tcm05) structure...")
    cursor.execute("""
        SELECT TOP 10 ce010, ce011, ce02, ce03, ce04, ce05, ce06, ce07, ce12
        FROM tcm05
        WHERE ce06 > 0
        ORDER BY ce011, ce02
    """)
    for row in cursor.fetchall():
        print(f"  Type={row.ce010}, Supplier={row.ce011}, Product={row.ce02}")
        print(f"    SupplierProdNo={row.ce03}, Seq={row.ce04}")
        print(f"    {row.ce05} {row.ce06} / {row.ce12}, Date={row.ce07}")

    # Query order structures
    print("\n6. Order (tfm01/tfm02) structure...")
    cursor.execute("""
        SELECT TOP 3 fa01, fa02, fa03, fa040, fa041, fa05, fa06, fa07, fa12, fa17, fa19, fa20
        FROM tfm01
        ORDER BY fa03 DESC
    """)
    print("  tfm01 (Order Master):")
    for row in cursor.fetchall():
        print(f"    OrderNo={row.fa01}, Type={row.fa02}, Date={row.fa03}")
        print(f"    CustomerType={row.fa040}, CustomerNo={row.fa041}")
        print(f"    Salesperson={row.fa05}, Attn={row.fa07}")
        print(f"    Terms={row.fa17}, Currency={row.fa19}, Amount={row.fa20}")

    cursor.execute("""
        SELECT TOP 5 fb01, fb02, fb03, fb06, fb07, fb09, fb10, fb15, fb16, fb13, fb14
        FROM tfm02
        ORDER BY fb01 DESC
    """)
    print("  tfm02 (Order Items):")
    for row in cursor.fetchall():
        print(f"    OrderNo={row.fb01}, Item={row.fb02}, ProductNo={row.fb03}")
        print(f"    Name={row.fb06}/{row.fb07}")
        print(f"    Qty={row.fb09} {row.fb10}, Currency={row.fb15}, Price={row.fb16}")
        print(f"    Supplier={row.fb13}, SupplierSeq={row.fb14}")

    # Query tem01/tem02 quotation structure
    print("\n7. Quotation (tem01/tem02) structure...")
    cursor.execute("SELECT TOP 3 ea01, ea02, ea03, ea040, ea041, ea05, ea07, ea17, ea19, ea20 FROM tem01 ORDER BY ea03 DESC")
    print("  tem01 (Quotation Master):")
    for row in cursor.fetchall():
        print(f"    QuotNo={row.ea01}, Type={row.ea02}, Date={row.ea03}")
        print(f"    CustType={row.ea040}, CustNo={row.ea041}")
        print(f"    Sales={row.ea05}, Attn={row.ea07}")
        print(f"    Terms={row.ea17}, Currency={row.ea19}, Amount={row.ea20}")

    cursor.close()
    conn.close()
    print("\nQuery completed!")

if __name__ == "__main__":
    main()
