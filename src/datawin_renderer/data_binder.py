"""
Data Binder - Fills EDIT fields with data from external sources
Mimics the FillData() function from nrp32.exe
"""

from typing import Dict, Any, Optional, List
import json
import csv
from pathlib import Path
from .parser import ReportDocument, EditElement, PlankElement


class DataBinder:
    """
    Binds data to EDIT fields in a report document

    Supports multiple data sources:
    - Dictionary (in-memory)
    - JSON file
    - CSV file
    - Custom data provider callback
    """

    def __init__(self, data_source: Optional[Dict[int, str]] = None):
        """
        Initialize DataBinder

        Args:
            data_source: Dictionary mapping EDIT field IDs to values
                        {0: "2024-01-15", 1: "ORD-12345", ...}
        """
        self.data_source = data_source or {}

    @classmethod
    def from_dict(cls, data: Dict[int, str]) -> 'DataBinder':
        """Create binder from dictionary"""
        return cls(data)

    @classmethod
    def from_json(cls, filepath: str) -> 'DataBinder':
        """
        Create binder from JSON file

        JSON format:
        {
            "0": "2024-01-15",
            "1": "ORD-12345",
            "2": "REF-67890"
        }
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Convert string keys to integers
        int_data = {int(k): v for k, v in data.items()}
        return cls(int_data)

    @classmethod
    def from_csv(cls, filepath: str, id_column: str = 'field_id',
                 value_column: str = 'value') -> 'DataBinder':
        """
        Create binder from CSV file

        CSV format:
        field_id,value
        0,2024-01-15
        1,ORD-12345
        2,REF-67890
        """
        data = {}
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                field_id = int(row[id_column])
                value = row[value_column]
                data[field_id] = value

        return cls(data)

    def set_field(self, field_id: int, value: str):
        """Set value for a specific field ID"""
        self.data_source[field_id] = value

    def get_field(self, field_id: int, default: str = "") -> str:
        """Get value for a specific field ID"""
        return self.data_source.get(field_id, default)

    def bind(self, document: ReportDocument):
        """
        Bind data to all EDIT fields in the document

        Args:
            document: ReportDocument to bind data to
        """
        # Process all elements
        for elem in document.elements:
            if isinstance(elem, EditElement):
                elem.bound_data = self.get_field(elem.id_num)
            elif isinstance(elem, PlankElement):
                # Process children in PLANK
                self._bind_plank(elem)

    def _bind_plank(self, plank: PlankElement):
        """Recursively bind data to elements in a PLANK"""
        for child in plank.children:
            if isinstance(child, EditElement):
                child.bound_data = self.get_field(child.id_num)
            elif isinstance(child, PlankElement):
                self._bind_plank(child)

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about data binding"""
        return {
            'total_fields': len(self.data_source),
            'field_ids': sorted(self.data_source.keys()),
        }

    def validate(self, document: ReportDocument) -> Dict[str, Any]:
        """
        Validate that all EDIT fields have data

        Returns:
            Dictionary with validation results:
            {
                'valid': bool,
                'missing_fields': [id1, id2, ...],
                'total_edits': int,
                'bound_edits': int
            }
        """
        all_edit_ids = set()

        def collect_edit_ids(elements: List):
            for elem in elements:
                if isinstance(elem, EditElement):
                    all_edit_ids.add(elem.id_num)
                elif isinstance(elem, PlankElement):
                    collect_edit_ids(elem.children)

        collect_edit_ids(document.elements)

        missing = []
        for edit_id in all_edit_ids:
            if edit_id not in self.data_source or not self.data_source[edit_id]:
                missing.append(edit_id)

        return {
            'valid': len(missing) == 0,
            'missing_fields': sorted(missing),
            'total_edits': len(all_edit_ids),
            'bound_edits': len(all_edit_ids) - len(missing)
        }


class DataBinderBuilder:
    """
    Fluent builder for creating complex data bindings

    Example:
        binder = (DataBinderBuilder()
                  .add_field(0, "2024-01-15")
                  .add_field(1, "ORD-12345")
                  .add_fields_from_dict({2: "REF-67890", 3: "CUST-001"})
                  .build())
    """

    def __init__(self):
        self.data = {}

    def add_field(self, field_id: int, value: str) -> 'DataBinderBuilder':
        """Add a single field"""
        self.data[field_id] = value
        return self

    def add_fields_from_dict(self, fields: Dict[int, str]) -> 'DataBinderBuilder':
        """Add multiple fields from dictionary"""
        self.data.update(fields)
        return self

    def add_fields_from_json(self, filepath: str) -> 'DataBinderBuilder':
        """Add fields from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        int_data = {int(k): v for k, v in data.items()}
        self.data.update(int_data)
        return self

    def build(self) -> DataBinder:
        """Build the DataBinder"""
        return DataBinder(self.data)


# Convenience functions for common use cases

def create_sample_data() -> DataBinder:
    """
    Create sample data for testing
    Based on typical PROFORMA INVOICE fields
    """
    builder = DataBinderBuilder()
    builder.add_field(0, "PROFORMA INVOICE")
    builder.add_field(1, "2024-01-15")
    builder.add_field(2, "ORD-2024-001")
    builder.add_field(3, "REF-ABC-123")
    builder.add_field(4, "CUST-12345")
    builder.add_field(5, "+886-2-1234-5678")
    builder.add_field(6, "+886-2-1234-5679")
    builder.add_field(7, "2024-02-15")
    builder.add_field(99, "Special Note")
    return builder.build()


def bind_invoice_data(document: ReportDocument,
                      order_no: str,
                      date: str,
                      customer_id: str,
                      reference: str = "",
                      tel: str = "",
                      fax: str = "",
                      etd: str = "") -> DataBinder:
    """
    Quick helper to bind common invoice fields

    Args:
        document: ReportDocument to bind
        order_no: Order number
        date: Invoice date
        customer_id: Customer ID
        reference: Reference number (optional)
        tel: Telephone (optional)
        fax: Fax number (optional)
        etd: Estimated time of delivery (optional)

    Returns:
        DataBinder instance with data already bound to document
    """
    builder = DataBinderBuilder()
    builder.add_field(1, date)
    builder.add_field(2, order_no)
    builder.add_field(3, reference)
    builder.add_field(4, customer_id)
    builder.add_field(5, tel)
    builder.add_field(6, fax)
    builder.add_field(7, etd)
    binder = builder.build()

    binder.bind(document)
    return binder
