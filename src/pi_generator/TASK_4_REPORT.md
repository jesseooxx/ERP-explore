# Task 4: Auto-naming and Filing Module - Implementation Report

## Task Overview
Implement automatic naming and filing functionality for PI PDF files according to the standard naming convention.

## Implementation Summary

### 1. Created `file_manager.py` Module

**Location:** `src/pi_generator/file_manager.py`

**Key Functions Implemented:**

#### Core Naming Functions
- `get_pi_filename(pi_data)` - Generates filename according to pattern: `PI_ {Ref} ({ORDER}).pdf`
- `get_pi_filepath(pi_data, base_dir)` - Generates full path: `{base_dir}\{Cust#}\PI_ {Ref} ({ORDER}).pdf`

#### File Operations
- `save_pi_pdf(pi_data, pdf_bytes, base_dir)` - Complete save operation with directory creation
- `ensure_directory_exists(directory)` - Creates directory structure if needed
- `list_pi_files(customer_code, base_dir)` - Lists all PI files for a customer

#### Utility Functions
- `sanitize_filename(filename)` - Removes invalid filename characters
- `validate_pi_data_for_filing(pi_data)` - Validates required fields are present
- `get_customer_directory(customer_code, base_dir)` - Gets customer subdirectory path

#### Exception
- `FileManagerError` - Custom exception for file management errors

### 2. Naming Convention Implementation

**Pattern:** `Z:\LEILA\PI\{Cust#}\PI_ {Ref} ({ORDER}).pdf`

**Components:**
- `{Cust#}` = Customer code from `pi_data.customer.code`
- `{Ref}` = S/C number from `pi_data.master.sc_no`
- `{ORDER}` = Customer PO from `pi_data.master.customer_po`

**Example:**
```
Input:  Customer: 161, S/C: T17104, PO: 11365
Output: Z:\LEILA\PI\161\PI_ T17104 (11365).pdf
```

### 3. Features Implemented

#### Automatic Directory Creation
- Creates customer subdirectories automatically if they don't exist
- Uses `Path.mkdir(parents=True, exist_ok=True)` for safe creation

#### Filename Sanitization
- Removes/replaces invalid Windows filename characters: `< > : " / \ | ? *`
- Handles edge cases like leading/trailing spaces

#### Data Validation
- Validates required fields (customer_code, sc_no, customer_po) before processing
- Raises `FileManagerError` with descriptive messages for missing fields
- Validates PDF bytes type and content

#### Configurable Base Directory
- Production path: `Z:\LEILA\PI` (default)
- Test path: configurable via `base_dir` parameter
- All functions support custom base directory

#### Path Handling
- Uses `pathlib.Path` for cross-platform path handling
- Properly handles Windows path separators

### 4. Updated `__init__.py`

Added exports for file management functions:
```python
from .file_manager import (
    get_pi_filename,
    get_pi_filepath,
    save_pi_pdf,
    ensure_directory_exists,
    get_customer_directory,
    list_pi_files,
    sanitize_filename,
    validate_pi_data_for_filing,
    FileManagerError
)
```

### 5. Comprehensive Testing

**Created:** `test_file_manager.py`

**Test Coverage:**
1. Filename Sanitization - Tests removal of invalid characters
2. Filename Generation - Validates correct filename pattern
3. Filepath Generation - Tests both production and test paths
4. Directory Creation - Verifies automatic directory creation
5. File Saving - Tests actual PDF file save operation
6. File Listing - Tests listing PI files for customers
7. PIData Validation - Tests validation of required fields
8. Edge Cases - Tests error handling for invalid inputs

**Test Results:** ALL 8 TESTS PASSED ✓

### 6. Integration Example

**Created:** `example_complete_workflow.py`

Demonstrates complete workflow:
1. Query PI data from database (Task 2)
2. Generate PDF (Task 3)
3. Save with proper naming and filing (Task 4)

**Example Run Results:**
```
Processing S/C: T17104
  Customer: 161 - Horizon Tool, Inc.
  S/C Number: T17104
  Customer PO: 11365
  Saved to: output\161\PI_ T17104 (11365).pdf

Processing S/C: T17103
  Customer: 491 - ASW Andreas Heuel GmbH
  S/C Number: T17103
  Customer PO: 1770066
  Saved to: output\491\PI_ T17103 (1770066).pdf

Processing S/C: I17109
  Customer: 497 - Wera Werk, sro
  S/C Number: I17109
  Customer PO: 93743
  Saved to: output\497\PI_ I17109 (93743).pdf
```

## Directory Structure Created

```
output/
├── 161/
│   └── PI_ T17104 (11365).pdf
├── 491/
│   └── PI_ T17103 (1770066).pdf
└── 497/
    └── PI_ I17109 (93743).pdf
```

Each customer has their own subdirectory with properly named PI files.

## Error Handling

### Validation Errors
- Missing customer code
- Missing S/C number
- Missing customer PO
- Empty or whitespace-only fields

### File Operation Errors
- Directory creation failures
- File write failures
- Invalid PDF bytes (empty or wrong type)

All errors raise `FileManagerError` with descriptive messages.

## Usage Examples

### Basic Usage
```python
from pi_generator import get_pi_data, generate_pi_pdf_bytes, save_pi_pdf

# Get PI data
pi_data = get_pi_data("T17104")

# Generate PDF
pdf_bytes = generate_pi_pdf_bytes(pi_data)

# Save to production location
saved_path = save_pi_pdf(pi_data, pdf_bytes)
# Result: Z:\LEILA\PI\161\PI_ T17104 (11365).pdf
```

### Test/Development Usage
```python
# Save to test location
saved_path = save_pi_pdf(pi_data, pdf_bytes, base_dir="output")
# Result: output\161\PI_ T17104 (11365).pdf
```

### Get Filepath Without Saving
```python
from pi_generator import get_pi_filepath

# Get production path
prod_path = get_pi_filepath(pi_data)
# Result: Z:\LEILA\PI\161\PI_ T17104 (11365).pdf

# Get test path
test_path = get_pi_filepath(pi_data, base_dir="output")
# Result: output\161\PI_ T17104 (11365).pdf
```

## Files Modified/Created

### Created
- `src/pi_generator/file_manager.py` - Main implementation (350+ lines)
- `test_file_manager.py` - Comprehensive test suite (350+ lines)
- `example_complete_workflow.py` - Integration example (180+ lines)
- `src/pi_generator/TASK_4_REPORT.md` - This report

### Modified
- `src/pi_generator/__init__.py` - Added file manager exports

## Testing Verification

### Manual Testing
```bash
# Run comprehensive test suite
python test_file_manager.py

# Run complete workflow example
python example_complete_workflow.py

# Test with specific S/C number
python test_file_manager.py T17104
python example_complete_workflow.py T17104
```

### Test Results Summary
- Filename Sanitization: PASS
- Filename Generation: PASS
- Filepath Generation: PASS
- Directory Creation: PASS
- File Saving: PASS
- File Listing: PASS
- PIData Validation: PASS
- Edge Cases: PASS

**Total: 8/8 tests passed (100%)**

## Technical Notes

### Windows Path Handling
- All docstrings with backslashes use raw strings (`r"""..."""`)
- Uses `pathlib.Path` for cross-platform compatibility
- Properly handles Windows path separators

### Logging
- Uses Python logging module
- Logs at INFO level for successful operations
- Logs at DEBUG level for detailed operations
- Logs at ERROR level for failures

### Code Quality
- Type hints for all functions
- Comprehensive docstrings with examples
- Error handling with custom exceptions
- Clean separation of concerns

## Issues and Concerns

### None Identified

All functionality works as expected:
- ✓ Naming convention correctly implemented
- ✓ Directory creation works properly
- ✓ File saving successful
- ✓ Validation catches all error cases
- ✓ Path handling works on Windows
- ✓ All tests pass

## Next Steps

Task 4 is complete and ready for integration. The module provides:
1. Automatic file naming according to specification
2. Automatic directory creation and management
3. Robust error handling and validation
4. Complete integration with Tasks 2 and 3

The PI generator now has complete functionality:
- **Task 2:** Query PI data from database ✓
- **Task 3:** Generate PDF from PI data ✓
- **Task 4:** Auto-naming and filing ✓

## Conclusion

Task 4 has been successfully implemented and tested. The file management module provides robust, production-ready functionality for automatically naming and filing PI PDF files according to the specified convention. All tests pass, error handling is comprehensive, and the module integrates seamlessly with the existing PI generator components.
