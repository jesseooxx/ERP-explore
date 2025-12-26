"""
Verify 284102 product data against documented field mappings
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
    print("284102 Product Data Verification")
    print("=" * 80)

    # 1. Query tdm01 - Product Basic Data
    print("\n1. tdm01 (Product Basic Data)")
    print("-" * 60)
    cursor.execute("""
        SELECT da01, da02, da03, da04, da05, da06,
               da07, da08, da09, da10, da11, da12,
               da24, da40, da41, da42, da55, da56
        FROM tdm01
        WHERE da01 LIKE '284102%'
        ORDER BY da01
    """)

    for row in cursor.fetchall():
        print(f"\nProduct: {row.da01}")
        print(f"  Name (da02): {row.da02}")
        print(f"  Spec (da03): {row.da03}")
        print(f"  Category (da04): {row.da04}")
        print(f"  Catalog (da05): {row.da05}")
        print(f"  Type (da06): {row.da06}")
        print(f"  Domestic Currency (da07): {row.da07}")
        print(f"  Domestic Price (da08): {row.da08}")
        print(f"  Export Currency (da09): {row.da09}")
        print(f"  Export Price (da10): {row.da10}")
        print(f"  Cost Currency (da11): {row.da11}")
        print(f"  Cost (da12): {row.da12}")
        print(f"  Unit (da24): {row.da24}")
        print(f"  Source (da40): {row.da40}")
        print(f"  Main Supplier (da41): {row.da41}")
        print(f"  Supplier Seq (da42): {row.da42}")
        print(f"  Create Date (da55): {row.da55}")
        print(f"  Creator (da56): {row.da56}")

    # 2. Query tdm02 - Product Description
    print("\n\n2. tdm02 (Product Description) for 284102")
    print("-" * 60)
    cursor.execute("""
        SELECT db01, db02, db03, db04
        FROM tdm02
        WHERE db01 = '284102'
        ORDER BY db03, db02
    """)

    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"  [{row.db03}] Seq {row.db02}: {row.db04}")
    else:
        print("  No description records found for 284102")

    # 3. Query tdm05 - Product BOM
    print("\n\n3. tdm05 (Product BOM) for 284102")
    print("-" * 60)
    cursor.execute("""
        SELECT de01, de02, de03, de04, de05, de06, de07, de09, de15, de18
        FROM tdm05
        WHERE de01 = '284102'
        ORDER BY de15
    """)

    rows = cursor.fetchall()
    if rows:
        print(f"  {'Component':<25} {'Ratio':<10} {'Supplier':<10} {'Seq':<5} {'Main':<5} {'Active':<6}")
        print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*5} {'-'*5} {'-'*6}")
        for row in rows:
            ratio = f"{row.de03}/{row.de04}"
            print(f"  {row.de02:<25} {ratio:<10} {row.de05 or '':<10} {row.de06 or '':<5} {row.de09 or '':<5} {row.de18 or '':<6}")
    else:
        print("  No BOM records found for 284102")

    # 4. Query tcm05 - Supplier-Product relationship
    print("\n\n4. tcm05 (Supplier-Product) for 284102*")
    print("-" * 60)
    cursor.execute("""
        SELECT ce010, ce011, ce02, ce03, ce04, ce05, ce06, ce07, ce12
        FROM tcm05
        WHERE ce02 LIKE '284102%'
        ORDER BY ce02, ce011, ce04
    """)

    rows = cursor.fetchall()
    if rows:
        print(f"  {'Type':<5} {'Supplier':<10} {'Product':<25} {'Seq':<5} {'Currency':<8} {'Price':<12} {'Unit':<6} {'Date':<10}")
        print(f"  {'-'*5} {'-'*10} {'-'*25} {'-'*5} {'-'*8} {'-'*12} {'-'*6} {'-'*10}")
        for row in rows:
            print(f"  {row.ce010 or '':<5} {row.ce011 or '':<10} {row.ce02:<25} {row.ce04:<5} {row.ce05 or '':<8} {row.ce06 or 0:<12.2f} {row.ce12 or '':<6} {row.ce07 or '':<10}")
    else:
        print("  No supplier records found for 284102*")

    # 5. Query tcm01 - Supplier info for related suppliers
    print("\n\n5. tcm01 (Supplier Info) for 284102 suppliers")
    print("-" * 60)
    cursor.execute("""
        SELECT ca01, ca02, ca03, ca04, ca09, ca10
        FROM tcm01
        WHERE ca01 IN ('B02', '2279', '02291')
    """)

    for row in cursor.fetchall():
        print(f"  {row.ca01}: {row.ca03} ({row.ca02})")
        print(f"    Tel: {row.ca09}, Fax: {row.ca10}")

    # 6. Check if 284102 exists in any orders
    print("\n\n6. tfm02 (Order Items) containing 284102")
    print("-" * 60)
    cursor.execute("""
        SELECT TOP 5 fb01, fb02, fb03, fb07, fb09, fb10, fb15, fb16
        FROM tfm02
        WHERE fb03 LIKE '284102%'
        ORDER BY fb01 DESC
    """)

    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"  Order {row.fb01}, Item {row.fb02}: {row.fb03}")
            print(f"    Name: {row.fb07}")
            print(f"    Qty: {row.fb09} {row.fb10}, Price: {row.fb15} {row.fb16}")
    else:
        print("  No orders found containing 284102")

    cursor.close()
    conn.close()

    print("\n" + "=" * 80)
    print("Verification Complete")
    print("=" * 80)

if __name__ == "__main__":
    main()
