"""
PI Data Query Module

This module provides functions to query PI (Proforma Invoice) data from the database.
It builds upon the db.py module and provides structured data classes for PI information.

Tables queried:
- tfm01: Sales Contract Master (S/C Master)
- tfm02: Sales Contract Details
- tbm01: Customer Master

Usage:
    from pi_generator.pi_data import get_pi_data

    pi_data = get_pi_data("T25C22")
    print(f"Customer: {pi_data.customer.name}")
    print(f"Total Amount: {pi_data.master.total_amount}")
    for detail in pi_data.details:
        print(f"{detail.product_code}: {detail.quantity} {detail.unit}")
"""

from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
import logging

from .db import DatabaseConnection

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class PICustomer:
    """Customer information from tbm01"""
    code: str              # ba01: 客戶編號
    name: str              # ba02: 客戶名稱
    short_name: str        # ba03: 客戶簡稱
    address: str           # ba05: 地址

    def __str__(self) -> str:
        return f"{self.code} - {self.name}"


@dataclass
class PIMaster:
    """Sales Contract Master information from tfm01"""
    sc_no: str                    # fa01: S/C 編號 (e.g., T25C22)
    create_date: str              # fa03: 建立日期 (YYYYMMDD format)
    customer_code: str            # fa04: 客戶編號
    customer_po: str              # fa08: 客戶訂單號 (客人的 PO)
    trade_terms: str              # fa18: 貿易條件說明 (e.g., FOB SHANGHAI)
    payment_terms: str            # fa34: 付款條件說明
    total_amount: float           # fa37: 總金額

    @property
    def formatted_date(self) -> str:
        """Convert YYYYMMDD to readable format"""
        if self.create_date and len(self.create_date) == 8:
            try:
                year = self.create_date[:4]
                month = self.create_date[4:6]
                day = self.create_date[6:8]
                return f"{year}-{month}-{day}"
            except (ValueError, IndexError):
                return self.create_date
        return self.create_date or ""

    def __str__(self) -> str:
        return f"S/C {self.sc_no} - Customer PO: {self.customer_po}"


@dataclass
class PIDetail:
    """Sales Contract Detail information from tfm02"""
    sc_no: str              # fb01: S/C 編號
    item_seq: int           # fb02: 項次序號
    product_code: str       # fb03: 產品編號
    product_name_1: str     # fb06: 品名1
    product_name_2: str     # fb07: 品名2
    quantity: float         # fb09: 數量
    unit: str               # fb10: 單位
    unit_price: float       # fb11: 單價
    amount: float           # fb12: 金額 (or calculated from qty * unit_price)

    @property
    def full_product_name(self) -> str:
        """Combine product names"""
        names = []
        if self.product_name_1:
            names.append(self.product_name_1.strip())
        if self.product_name_2:
            names.append(self.product_name_2.strip())
        return " ".join(names)

    @property
    def calculated_amount(self) -> float:
        """Calculate amount from quantity * unit_price"""
        return self.quantity * self.unit_price

    def __str__(self) -> str:
        return f"{self.item_seq}. {self.product_code}: {self.quantity} {self.unit} @ ${self.unit_price}"


@dataclass
class PIData:
    """Complete PI data structure"""
    master: PIMaster
    details: List[PIDetail]
    customer: PICustomer

    @property
    def is_valid(self) -> bool:
        """Check if PI data is valid"""
        return (
            self.master is not None and
            self.customer is not None and
            len(self.details) > 0
        )

    @property
    def item_count(self) -> int:
        """Get number of line items"""
        return len(self.details)

    @property
    def calculated_total(self) -> float:
        """Calculate total from details using calculated_amount (qty * unit_price)"""
        return sum(detail.calculated_amount for detail in self.details)

    def __str__(self) -> str:
        return (
            f"PI Data for S/C {self.master.sc_no}\n"
            f"Customer: {self.customer}\n"
            f"Items: {self.item_count}\n"
            f"Total: ${self.master.total_amount:,.2f}"
        )


class PIDataQueryError(Exception):
    """Exception raised when PI data query fails"""
    pass


def get_pi_data(sc_no: str, db: Optional[DatabaseConnection] = None) -> PIData:
    """
    Query complete PI data for a given S/C number.

    Args:
        sc_no: Sales Contract number (e.g., "T25C22")
        db: Optional DatabaseConnection instance. If not provided, creates a new one.

    Returns:
        PIData: Complete PI data structure

    Raises:
        PIDataQueryError: If data is not found or invalid

    Example:
        pi_data = get_pi_data("T25C22")
        print(f"Customer: {pi_data.customer.name}")
        print(f"Total: ${pi_data.master.total_amount:,.2f}")
        for detail in pi_data.details:
            print(f"  {detail}")
    """
    # Strip and uppercase the S/C number
    sc_no = sc_no.strip().upper()

    # Use provided db connection or create new one
    should_close = False
    if db is None:
        db = DatabaseConnection()
        should_close = True

    try:
        # Query master data
        master = _get_master_data(sc_no, db)
        if master is None:
            raise PIDataQueryError(f"S/C {sc_no} not found in tfm01")

        # Query customer data
        customer = _get_customer_data(master.customer_code, db)
        if customer is None:
            raise PIDataQueryError(
                f"Customer {master.customer_code} not found in tbm01"
            )

        # Query detail data
        details = _get_detail_data(sc_no, db)
        if not details:
            raise PIDataQueryError(f"No details found for S/C {sc_no} in tfm02")

        # Create and validate PI data
        pi_data = PIData(
            master=master,
            details=details,
            customer=customer
        )

        if not pi_data.is_valid:
            raise PIDataQueryError(f"Invalid PI data for S/C {sc_no}")

        # Validate totals match
        calculated = pi_data.calculated_total
        master_total = pi_data.master.total_amount
        if abs(calculated - master_total) > 0.01:  # Allow small rounding differences
            logger.warning(
                f"Total mismatch for {sc_no}: "
                f"Master={master_total:.2f}, Calculated={calculated:.2f}"
            )

        logger.info(f"Successfully loaded PI data for {sc_no} with {pi_data.item_count} items")
        return pi_data

    except PIDataQueryError:
        raise
    except Exception as e:
        logger.error(f"Error querying PI data for {sc_no}: {e}")
        raise PIDataQueryError(f"Failed to query PI data for {sc_no}: {e}")
    finally:
        if should_close:
            db.close()


def _get_master_data(sc_no: str, db: DatabaseConnection) -> Optional[PIMaster]:
    """
    Query master data from tfm01.

    Args:
        sc_no: S/C number
        db: Database connection

    Returns:
        PIMaster or None if not found
    """
    sql = """
        SELECT
            fa01,  -- S/C 編號
            fa03,  -- 建立日期
            fa04,  -- 客戶編號
            fa08,  -- 客戶訂單號
            fa18,  -- 貿易條件說明
            fa34,  -- 付款條件說明
            fa37   -- 總金額
        FROM tfm01
        WHERE fa01 = ?
    """

    try:
        rows = db.execute_query(sql, (sc_no,))

        if not rows:
            logger.warning(f"No master data found for S/C {sc_no}")
            return None

        row = rows[0]

        return PIMaster(
            sc_no=row.fa01.strip() if row.fa01 else "",
            create_date=row.fa03.strip() if row.fa03 else "",
            customer_code=row.fa04.strip() if row.fa04 else "",
            customer_po=row.fa08.strip() if row.fa08 else "",
            trade_terms=row.fa18.strip() if row.fa18 else "",
            payment_terms=row.fa34.strip() if row.fa34 else "",
            total_amount=float(row.fa37) if row.fa37 else 0.0
        )

    except Exception as e:
        logger.error(f"Error querying master data for {sc_no}: {e}")
        raise


def _get_customer_data(customer_code: str, db: DatabaseConnection) -> Optional[PICustomer]:
    """
    Query customer data from tbm01.

    Args:
        customer_code: Customer code
        db: Database connection

    Returns:
        PICustomer or None if not found
    """
    sql = """
        SELECT
            ba01,  -- 客戶編號
            ba02,  -- 客戶名稱
            ba03,  -- 客戶簡稱
            ba05   -- 地址
        FROM tbm01
        WHERE ba01 = ?
    """

    try:
        rows = db.execute_query(sql, (customer_code,))

        if not rows:
            logger.warning(f"No customer data found for code {customer_code}")
            return None

        row = rows[0]

        return PICustomer(
            code=row.ba01.strip() if row.ba01 else "",
            name=row.ba02.strip() if row.ba02 else "",
            short_name=row.ba03.strip() if row.ba03 else "",
            address=row.ba05.strip() if row.ba05 else ""
        )

    except Exception as e:
        logger.error(f"Error querying customer data for {customer_code}: {e}")
        raise


def _get_detail_data(sc_no: str, db: DatabaseConnection) -> List[PIDetail]:
    """
    Query detail data from tfm02.

    Args:
        sc_no: S/C number
        db: Database connection

    Returns:
        List of PIDetail objects
    """
    sql = """
        SELECT
            fb01,  -- S/C 編號
            fb02,  -- 項次序號
            fb03,  -- 產品編號
            fb06,  -- 品名1
            fb07,  -- 品名2
            fb09,  -- 數量
            fb10,  -- 單位
            fb11,  -- 單價
            fb12   -- 金額
        FROM tfm02
        WHERE fb01 = ?
        ORDER BY fb02
    """

    try:
        rows = db.execute_query(sql, (sc_no,))

        details = []
        for row in rows:
            detail = PIDetail(
                sc_no=row.fb01.strip() if row.fb01 else "",
                item_seq=int(row.fb02) if row.fb02 else 0,
                product_code=row.fb03.strip() if row.fb03 else "",
                product_name_1=row.fb06.strip() if row.fb06 else "",
                product_name_2=row.fb07.strip() if row.fb07 else "",
                quantity=float(row.fb09) if row.fb09 else 0.0,
                unit=row.fb10.strip() if row.fb10 else "",
                unit_price=float(row.fb11) if row.fb11 else 0.0,
                amount=float(row.fb12) if row.fb12 else 0.0
            )
            details.append(detail)

        logger.info(f"Found {len(details)} detail records for S/C {sc_no}")
        return details

    except Exception as e:
        logger.error(f"Error querying detail data for {sc_no}: {e}")
        raise


def list_recent_sc_numbers(limit: int = 10, db: Optional[DatabaseConnection] = None) -> List[str]:
    """
    List recent S/C numbers for testing purposes.

    Args:
        limit: Maximum number of S/C numbers to return
        db: Optional DatabaseConnection instance

    Returns:
        List of S/C numbers
    """
    should_close = False
    if db is None:
        db = DatabaseConnection()
        should_close = True

    try:
        sql = """
            SELECT TOP (?) fa01
            FROM tfm01
            WHERE fa01 IS NOT NULL AND fa01 != ''
            ORDER BY fa03 DESC
        """

        rows = db.execute_query(sql, (limit,))
        sc_numbers = [row.fa01.strip() for row in rows if row.fa01]

        logger.info(f"Found {len(sc_numbers)} recent S/C numbers")
        return sc_numbers

    except Exception as e:
        logger.error(f"Error listing S/C numbers: {e}")
        return []
    finally:
        if should_close:
            db.close()


if __name__ == "__main__":
    # Test the module
    import sys

    print("\n" + "=" * 60)
    print("PI Data Query Module - Test")
    print("=" * 60 + "\n")

    # Check for command line argument
    if len(sys.argv) > 1:
        test_sc_no = sys.argv[1]
    else:
        # List recent S/C numbers
        print("Listing recent S/C numbers...")
        recent = list_recent_sc_numbers(5)
        if recent:
            print("\nRecent S/C numbers:")
            for i, sc_no in enumerate(recent, 1):
                print(f"  {i}. {sc_no}")
            test_sc_no = recent[0]
            print(f"\nUsing: {test_sc_no}")
        else:
            print("No S/C numbers found")
            sys.exit(1)

    # Test get_pi_data
    try:
        print(f"\nQuerying PI data for {test_sc_no}...")
        print("-" * 60)

        pi_data = get_pi_data(test_sc_no)

        print("\n" + str(pi_data))
        print("\n" + "=" * 60)
        print("MASTER DATA")
        print("=" * 60)
        print(f"S/C Number:      {pi_data.master.sc_no}")
        print(f"Create Date:     {pi_data.master.formatted_date}")
        print(f"Customer PO:     {pi_data.master.customer_po}")
        print(f"Trade Terms:     {pi_data.master.trade_terms}")
        print(f"Payment Terms:   {pi_data.master.payment_terms}")
        print(f"Total Amount:    ${pi_data.master.total_amount:,.2f}")

        print("\n" + "=" * 60)
        print("CUSTOMER DATA")
        print("=" * 60)
        print(f"Code:            {pi_data.customer.code}")
        print(f"Name:            {pi_data.customer.name}")
        print(f"Short Name:      {pi_data.customer.short_name}")
        print(f"Address:         {pi_data.customer.address}")

        print("\n" + "=" * 60)
        print(f"DETAILS ({pi_data.item_count} items)")
        print("=" * 60)
        for detail in pi_data.details:
            print(f"\n{detail.item_seq}. {detail.product_code}")
            print(f"   Name:     {detail.full_product_name}")
            print(f"   Qty:      {detail.quantity:,.2f} {detail.unit}")
            print(f"   Price:    ${detail.unit_price:,.2f}")
            print(f"   Amount:   ${detail.amount:,.2f}")

        print("\n" + "=" * 60)
        print("VALIDATION")
        print("=" * 60)
        print(f"Master Total:     ${pi_data.master.total_amount:,.2f}")
        print(f"Calculated Total: ${pi_data.calculated_total:,.2f}")
        print(f"Difference:       ${abs(pi_data.master.total_amount - pi_data.calculated_total):,.2f}")
        print(f"Valid:            {pi_data.is_valid}")

        print("\n" + "=" * 60)
        print("SUCCESS")
        print("=" * 60 + "\n")

    except PIDataQueryError as e:
        print(f"\nERROR: {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\nUNEXPECTED ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
