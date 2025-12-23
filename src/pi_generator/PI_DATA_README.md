# PI Data Query Module

## Overview

The `pi_data.py` module provides a structured interface for querying PI (Proforma Invoice) data from the DATAWIN database. It builds on the `db.py` database connection module and organizes data into Python data classes for easy manipulation.

## Features

- **Structured Data Classes**: PIData, PIMaster, PIDetail, PICustomer
- **Automatic Data Fetching**: Query all related data with a single function call
- **Data Validation**: Built-in validation and error handling
- **Type Safety**: Using Python dataclasses with type hints
- **Logging**: Comprehensive logging for debugging

## Quick Start

```python
from pi_generator.pi_data import get_pi_data

# Get complete PI data for a S/C number
pi_data = get_pi_data("T17104")

# Access master data
print(f"S/C: {pi_data.master.sc_no}")
print(f"Customer PO: {pi_data.master.customer_po}")
print(f"Total: ${pi_data.master.total_amount:,.2f}")

# Access customer data
print(f"Customer: {pi_data.customer.name}")
print(f"Address: {pi_data.customer.address}")

# Access details
for detail in pi_data.details:
    print(f"{detail.product_code}: {detail.quantity} {detail.unit}")
```

## Data Classes

### PIData
Main container for complete PI information.

**Properties:**
- `master`: PIMaster - Sales contract master data
- `details`: List[PIDetail] - List of line items
- `customer`: PICustomer - Customer information
- `is_valid`: bool - Data validation status
- `item_count`: int - Number of line items
- `calculated_total`: float - Sum of all line item amounts

### PIMaster
Sales Contract Master information from `tfm01`.

**Fields:**
- `sc_no`: str - S/C number (fa01)
- `create_date`: str - Create date in YYYYMMDD format (fa03)
- `customer_code`: str - Customer code (fa04)
- `customer_po`: str - Customer PO number (fa08)
- `trade_terms`: str - Trade terms, e.g., "FOB SHANGHAI" (fa18)
- `payment_terms`: str - Payment terms (fa34)
- `total_amount`: float - Total amount (fa37)

**Properties:**
- `formatted_date`: str - Date in YYYY-MM-DD format

### PIDetail
Sales Contract Detail information from `tfm02`.

**Fields:**
- `sc_no`: str - S/C number (fb01)
- `item_seq`: int - Item sequence number (fb02)
- `product_code`: str - Product code (fb03)
- `product_name_1`: str - Product name line 1 (fb06)
- `product_name_2`: str - Product name line 2 (fb07)
- `quantity`: float - Quantity (fb09)
- `unit`: str - Unit of measure (fb10)
- `unit_price`: float - Unit price (fb11)
- `amount`: float - Line amount from database (fb12)

**Properties:**
- `full_product_name`: str - Combined product name
- `calculated_amount`: float - Calculated as quantity × unit_price

### PICustomer
Customer information from `tbm01`.

**Fields:**
- `code`: str - Customer code (ba01)
- `name`: str - Customer full name (ba02)
- `short_name`: str - Customer short name (ba03)
- `address`: str - Customer address (ba05)

## Functions

### get_pi_data(sc_no: str, db: Optional[DatabaseConnection] = None) -> PIData

Query complete PI data for a given S/C number.

**Parameters:**
- `sc_no`: Sales Contract number (e.g., "T25C22")
- `db`: Optional DatabaseConnection instance (creates new if not provided)

**Returns:**
- `PIData`: Complete PI data structure

**Raises:**
- `PIDataQueryError`: If data is not found or invalid

**Example:**
```python
try:
    pi_data = get_pi_data("T17104")
    print(f"Loaded {pi_data.item_count} items")
except PIDataQueryError as e:
    print(f"Error: {e}")
```

### list_recent_sc_numbers(limit: int = 10, db: Optional[DatabaseConnection] = None) -> List[str]

List recent S/C numbers for testing purposes.

**Parameters:**
- `limit`: Maximum number of S/C numbers to return (default: 10)
- `db`: Optional DatabaseConnection instance

**Returns:**
- `List[str]`: List of S/C numbers ordered by date (newest first)

**Example:**
```python
recent = list_recent_sc_numbers(5)
for sc_no in recent:
    print(sc_no)
```

## Database Tables

The module queries three main tables:

### tfm01 - Sales Contract Master
Primary table containing order header information.

### tfm02 - Sales Contract Details
Line items for each order, linked by S/C number (fb01 = fa01).

### tbm01 - Customer Master
Customer information, linked by customer code (ba01 = fa04).

## Error Handling

The module defines a custom exception:

```python
class PIDataQueryError(Exception):
    """Exception raised when PI data query fails"""
```

This exception is raised when:
- S/C number not found in tfm01
- Customer not found in tbm01
- No details found in tfm02
- Data validation fails

## Important Notes

### Amount Calculation

**Note**: In the current database, the `fb12` field (amount) may not always contain accurate values. The module provides a `calculated_amount` property on `PIDetail` that calculates the amount as `quantity × unit_price`. This is typically more reliable for calculations.

When using the data:
- Use `detail.calculated_amount` for accurate per-line amounts
- Use `pi_data.calculated_total` for accurate total (sum of calculated amounts)
- `master.total_amount` is the value from the database (fa37)

There may be discrepancies between `master.total_amount` and `calculated_total` due to:
- Database data entry issues
- Discounts or adjustments not reflected in line items
- Currency conversion or rounding

### Data Validation

The module performs basic validation:
- Master record exists
- Customer record exists
- At least one detail record exists
- Logs warning if calculated total differs from master total by more than $0.01

## Testing

Run the test suite:

```bash
python src/pi_generator/test_pi_data.py
```

Run the example script:

```bash
python src/pi_generator/example_pi_data.py
```

Run as module to test a specific S/C:

```bash
python -m pi_generator.pi_data T17104
```

## Dependencies

- `pyodbc`: Database connectivity
- `dataclasses`: Data structure (Python 3.7+)
- `typing`: Type hints
- `logging`: Logging support

Requires the `db.py` module from the same package.

## Usage in PI Generator

This module is designed to be used by the PDF generation module (Task 3). It provides clean, structured data that can be easily formatted into PDF reports:

```python
# In PDF generator module
from pi_generator.pi_data import get_pi_data

def generate_pi_pdf(sc_no: str):
    # Get data
    pi_data = get_pi_data(sc_no)

    # Use data to generate PDF
    add_customer_info(pi_data.customer)
    add_order_details(pi_data.master)
    add_line_items(pi_data.details)
    # ...
```

## Future Enhancements

Potential improvements:
- Caching for frequently accessed S/C numbers
- Batch querying for multiple S/C numbers
- Additional validation rules
- Currency conversion support
- Discount and tax calculation
- Export to other formats (JSON, CSV, etc.)

## Support

For issues or questions, refer to:
- Database schema documentation
- Task implementation notes
- Test cases in `test_pi_data.py`
