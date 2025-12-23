# PI Generator - Database Module

Database connection module for the PI (Proforma Invoice) Report Generator.

## Overview

This module provides a robust database connectivity layer for accessing the DATAWIN SQL Server database. It bypasses the ERP/NRP rendering system and allows direct SQL queries for generating PI reports.

## Features

- **Connection Management**: Automatic connection pooling and reconnection
- **Windows Authentication**: Uses Windows trusted connection (no password needed)
- **Error Handling**: Comprehensive error handling with logging
- **Multiple Result Formats**: Return results as rows, dictionaries, or scalar values
- **Parameterized Queries**: Safe query execution with parameter binding
- **Transaction Support**: Context manager for database transactions
- **Table Introspection**: Get table structure and metadata
- **Driver Fallback**: Automatically tries ODBC Driver 17, then falls back to SQL Server driver

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure SQL Server is running and the DATAWIN database is accessible.

## Quick Start

### Basic Usage

```python
from db import DatabaseConnection

# Context manager (recommended)
with DatabaseConnection() as db:
    results = db.execute_query("SELECT TOP 5 * FROM tfm01")
    for row in results:
        print(row.fa01, row.fa07)
```

### Parameterized Queries

```python
with DatabaseConnection() as db:
    # Safe from SQL injection
    results = db.execute_dict(
        "SELECT * FROM tfm01 WHERE fa01 = ?",
        ("T16C04",)
    )
    print(results[0])  # Dictionary with column names as keys
```

### Get Single Value

```python
with DatabaseConnection() as db:
    count = db.execute_scalar("SELECT COUNT(*) FROM tfm01")
    print(f"Total records: {count}")
```

### Table Information

```python
with DatabaseConnection() as db:
    columns = db.get_table_info("tfm01")
    for col in columns:
        print(f"{col['COLUMN_NAME']}: {col['DATA_TYPE']}")
```

### Transactions

```python
with DatabaseConnection() as db:
    with db.transaction():
        db.execute_query("INSERT INTO ...", params)
        db.execute_query("UPDATE ...", params)
    # Auto-commits on success, rolls back on error
```

## API Reference

### DatabaseConnection Class

#### Methods

- `get_connection()` - Get or create database connection
- `execute_query(sql, params=None)` - Execute query, return rows
- `execute_dict(sql, params=None)` - Execute query, return list of dictionaries
- `execute_scalar(sql, params=None)` - Execute query, return single value
- `test_connection()` - Test if connection is working
- `get_table_info(table_name)` - Get column information for table
- `close()` - Close database connection
- `transaction()` - Context manager for transactions

### Convenience Functions

```python
from db import get_connection, execute_query, test_connection

# Quick access functions
conn = get_connection()
results = execute_query("SELECT * FROM tfm01", ("param",))
success = test_connection()
```

## Configuration

Database settings are in the `DatabaseConfig` class:

```python
class DatabaseConfig:
    SERVER = "localhost"
    DATABASE = "DATAWIN"
    DRIVER = "{ODBC Driver 17 for SQL Server}"
    TRUSTED_CONNECTION = "yes"
```

To use custom settings:

```python
from db import DatabaseConnection, DatabaseConfig

config = DatabaseConfig()
config.DATABASE = "DATAWIN_TEST"

db = DatabaseConnection(config)
```

## Testing

Run the test suite:

```bash
cd src/pi_generator
python test_db_connection.py
```

This will run 4 comprehensive tests:
1. Basic connection test
2. Query execution test
3. Parameterized query test
4. Table existence check

## Examples

See `example_usage.py` for detailed usage examples:

```bash
cd src/pi_generator
python example_usage.py
```

Examples include:
- Basic queries
- Parameterized queries
- Scalar queries
- Table information
- Complex joins

## Database Schema

### Main Tables

- **tfm01**: S/C (Sales Contract) master table
  - fa01: S/C number
  - fa03: Customer code
  - fa04: Date
  - fa07: Customer name
  - fa08: PO number

- **tfm02**: S/C detail table
  - fb01: S/C number (foreign key)
  - fb02: Item number
  - fb03: Product code
  - fb06: Product name
  - fb09: Quantity
  - fb10: Unit

- **tqm01**: Quotation master table
- **tqm02**: Quotation detail table

## Error Handling

The module includes comprehensive error handling:

```python
try:
    with DatabaseConnection() as db:
        results = db.execute_query("SELECT * FROM tfm01")
except pyodbc.Error as e:
    print(f"Database error: {e}")
```

All errors are logged using Python's logging module.

## Logging

The module uses Python's logging framework:

```python
import logging

# Set logging level
logging.basicConfig(level=logging.DEBUG)
```

Log levels:
- INFO: Connection status, query results
- DEBUG: SQL queries and parameters
- ERROR: Connection failures, query errors

## Performance Tips

1. Use context managers to ensure connections are properly closed
2. Use parameterized queries for better query plan caching
3. Fetch only the columns you need
4. Use `execute_scalar()` for single values instead of `execute_query()`
5. Connection is reused within a DatabaseConnection instance

## Security

- Always use parameterized queries to prevent SQL injection
- Uses Windows Authentication (no hardcoded credentials)
- Connection strings don't contain passwords
- All queries are logged for audit purposes

## Troubleshooting

### Connection Fails

1. Check SQL Server is running: `sqlcmd -S localhost -Q "SELECT @@VERSION" -E`
2. Verify database exists: `sqlcmd -S localhost -Q "SELECT name FROM sys.databases" -E`
3. Check ODBC drivers: Look for "ODBC Driver 17 for SQL Server" in Windows ODBC Data Sources

### Driver Not Found

If ODBC Driver 17 is not installed, the module automatically falls back to the older "SQL Server" driver. To install ODBC Driver 17:
- Download from Microsoft: "ODBC Driver 17 for SQL Server"

### Authentication Issues

- Ensure you're running as a user with SQL Server access
- Check SQL Server allows Windows Authentication
- Verify user has permissions on DATAWIN database

## Future Enhancements

- [ ] Connection pooling across multiple DatabaseConnection instances
- [ ] Async query support
- [ ] Query result caching
- [ ] Performance monitoring
- [ ] Automatic retry logic
- [ ] Schema change detection

## License

Part of the ERP Explore project.

## Contact

For issues or questions, please refer to the main project documentation.
