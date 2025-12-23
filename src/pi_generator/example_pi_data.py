"""
Example usage of PI Data Query Module

This script demonstrates how to use the pi_data module to query PI information.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pi_generator.pi_data import get_pi_data, list_recent_sc_numbers, PIDataQueryError


def main():
    """Main function demonstrating module usage"""

    print("\n" + "=" * 70)
    print("PI Data Module - Usage Example")
    print("=" * 70)

    # Example 1: List recent S/C numbers
    print("\n1. Listing recent S/C numbers:")
    print("-" * 70)

    recent_sc = list_recent_sc_numbers(5)
    if recent_sc:
        print(f"\nFound {len(recent_sc)} recent S/C numbers:")
        for i, sc_no in enumerate(recent_sc, 1):
            print(f"  {i}. {sc_no}")

        # Example 2: Get PI data for the first S/C
        test_sc = recent_sc[0]
        print(f"\n\n2. Getting PI data for {test_sc}:")
        print("-" * 70)

        try:
            pi_data = get_pi_data(test_sc)

            # Access master data
            print(f"\nS/C Number:    {pi_data.master.sc_no}")
            print(f"Date:          {pi_data.master.formatted_date}")
            print(f"Customer PO:   {pi_data.master.customer_po}")
            print(f"Trade Terms:   {pi_data.master.trade_terms}")
            print(f"Payment Terms: {pi_data.master.payment_terms}")

            # Access customer data
            print(f"\nCustomer:      {pi_data.customer.name}")
            print(f"Code:          {pi_data.customer.code}")
            print(f"Short Name:    {pi_data.customer.short_name}")
            print(f"Address:       {pi_data.customer.address[:50]}...")

            # Access details
            print(f"\nItems:         {pi_data.item_count}")
            print(f"Total Amount:  ${pi_data.master.total_amount:,.2f}")

            # Show first few items
            print("\nFirst 3 items:")
            for detail in pi_data.details[:3]:
                print(f"  - {detail.product_code}: {detail.full_product_name}")
                print(f"    {detail.quantity:,.2f} {detail.unit} @ ${detail.unit_price:,.4f} = ${detail.calculated_amount:,.2f}")

            print(f"\nValidation:")
            print(f"  Is Valid:       {pi_data.is_valid}")
            print(f"  Calculated Sum: ${pi_data.calculated_total:,.2f}")

        except PIDataQueryError as e:
            print(f"\nError: {e}")

    else:
        print("\nNo S/C numbers found!")

    # Example 3: Error handling
    print(f"\n\n3. Error handling example:")
    print("-" * 70)

    try:
        invalid_data = get_pi_data("INVALID_123")
    except PIDataQueryError as e:
        print(f"\nCaught expected error: {e}")

    print("\n" + "=" * 70)
    print("Example completed!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
