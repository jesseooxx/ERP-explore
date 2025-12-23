"""
Database Connection Module for PI Generator

This module provides database connectivity to the DATAWIN_LOCAL SQL Server database.
It uses pyodbc with Windows Authentication and includes connection pooling,
error handling, and utility functions for querying.
"""

import pyodbc
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Database configuration settings"""

    SERVER = "localhost"
    DATABASE = "DATAWIN"  # Changed from DATAWIN_LOCAL to DATAWIN (the actual database name)
    DRIVER = "{ODBC Driver 17 for SQL Server}"  # Fallback to SQL Server driver if not available
    TRUSTED_CONNECTION = "yes"

    @classmethod
    def get_connection_string(cls) -> str:
        """Generate ODBC connection string"""
        return (
            f"DRIVER={cls.DRIVER};"
            f"SERVER={cls.SERVER};"
            f"DATABASE={cls.DATABASE};"
            f"Trusted_Connection={cls.TRUSTED_CONNECTION};"
        )

    @classmethod
    def get_fallback_connection_string(cls) -> str:
        """Generate fallback connection string with older SQL Server driver"""
        fallback_driver = "{SQL Server}"
        return (
            f"DRIVER={fallback_driver};"
            f"SERVER={cls.SERVER};"
            f"DATABASE={cls.DATABASE};"
            f"Trusted_Connection={cls.TRUSTED_CONNECTION};"
        )


class DatabaseConnection:
    """
    Database connection manager with connection pooling and error handling.

    Usage:
        db = DatabaseConnection()

        # Test connection
        if db.test_connection():
            # Execute query
            results = db.execute_query("SELECT * FROM tfm01 WHERE fa01 = ?", ("T16C04",))
            for row in results:
                print(row)
    """

    def __init__(self, config: Optional[DatabaseConfig] = None):
        """
        Initialize database connection manager.

        Args:
            config: Optional DatabaseConfig instance. Uses default if not provided.
        """
        self.config = config or DatabaseConfig()
        self._connection: Optional[pyodbc.Connection] = None

    def get_connection(self) -> pyodbc.Connection:
        """
        Get or create a database connection.

        Returns:
            pyodbc.Connection: Active database connection

        Raises:
            pyodbc.Error: If connection fails
        """
        if self._connection is None or not self._is_connection_alive():
            self._connection = self._create_connection()
        return self._connection

    def _create_connection(self) -> pyodbc.Connection:
        """
        Create a new database connection.

        Returns:
            pyodbc.Connection: New database connection

        Raises:
            pyodbc.Error: If connection fails
        """
        try:
            # Try with ODBC Driver 17 first
            conn_str = self.config.get_connection_string()
            logger.info(f"Attempting connection to {self.config.DATABASE} on {self.config.SERVER}")
            connection = pyodbc.connect(conn_str, timeout=10)
            logger.info("Successfully connected to database using ODBC Driver 17")
            return connection

        except pyodbc.Error as e:
            # Try fallback driver
            logger.warning(f"ODBC Driver 17 failed, trying fallback driver: {e}")
            try:
                conn_str = self.config.get_fallback_connection_string()
                connection = pyodbc.connect(conn_str, timeout=10)
                logger.info("Successfully connected to database using SQL Server driver")
                return connection
            except pyodbc.Error as fallback_error:
                logger.error(f"Database connection failed: {fallback_error}")
                raise

    def _is_connection_alive(self) -> bool:
        """
        Check if the current connection is still alive.

        Returns:
            bool: True if connection is alive, False otherwise
        """
        if self._connection is None:
            return False

        try:
            # Try a simple query to test connection
            cursor = self._connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return True
        except (pyodbc.Error, AttributeError):
            return False

    def execute_query(
        self,
        sql: str,
        params: Optional[Tuple] = None,
        fetch_all: bool = True
    ) -> List[pyodbc.Row]:
        """
        Execute a SQL query and return results.

        Args:
            sql: SQL query string (use ? for parameters)
            params: Optional tuple of parameters for parameterized query
            fetch_all: If True, fetch all results. If False, returns cursor.

        Returns:
            List of pyodbc.Row objects containing query results

        Raises:
            pyodbc.Error: If query execution fails

        Example:
            results = db.execute_query(
                "SELECT * FROM tfm01 WHERE fa01 = ?",
                ("T16C04",)
            )
        """
        connection = self.get_connection()
        cursor = connection.cursor()

        try:
            if params:
                logger.debug(f"Executing query with params: {sql[:100]}...")
                cursor.execute(sql, params)
            else:
                logger.debug(f"Executing query: {sql[:100]}...")
                cursor.execute(sql)

            if fetch_all:
                results = cursor.fetchall()
                logger.info(f"Query returned {len(results)} rows")
                return results
            else:
                return cursor

        except pyodbc.Error as e:
            logger.error(f"Query execution failed: {e}")
            logger.error(f"SQL: {sql}")
            logger.error(f"Params: {params}")
            raise
        finally:
            if fetch_all:
                cursor.close()

    def execute_scalar(self, sql: str, params: Optional[Tuple] = None) -> Any:
        """
        Execute a query and return a single value.

        Args:
            sql: SQL query string
            params: Optional tuple of parameters

        Returns:
            Single value from the first row, first column

        Example:
            count = db.execute_scalar("SELECT COUNT(*) FROM tfm01")
        """
        cursor = self.execute_query(sql, params, fetch_all=False)
        try:
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            cursor.close()

    def execute_dict(
        self,
        sql: str,
        params: Optional[Tuple] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a query and return results as list of dictionaries.

        Args:
            sql: SQL query string
            params: Optional tuple of parameters

        Returns:
            List of dictionaries with column names as keys

        Example:
            orders = db.execute_dict("SELECT * FROM tfm01 WHERE fa01 = ?", ("T16C04",))
            for order in orders:
                print(order['fa01'], order['fa03'])
        """
        rows = self.execute_query(sql, params)

        if not rows:
            return []

        # Get column names from cursor description
        columns = [column[0] for column in rows[0].cursor_description]

        # Convert rows to dictionaries
        result = []
        for row in rows:
            result.append(dict(zip(columns, row)))

        return result

    @contextmanager
    def transaction(self):
        """
        Context manager for database transactions.

        Usage:
            with db.transaction():
                db.execute_query("INSERT INTO ...", params)
                db.execute_query("UPDATE ...", params)
            # Auto-commits on success, rolls back on exception
        """
        connection = self.get_connection()
        try:
            yield connection
            connection.commit()
            logger.info("Transaction committed")
        except Exception as e:
            connection.rollback()
            logger.error(f"Transaction rolled back: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test if database connection is working.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            connection = self.get_connection()
            cursor = connection.cursor()

            # Test basic query
            cursor.execute("SELECT @@VERSION as version, DB_NAME() as database_name")
            result = cursor.fetchone()

            logger.info("=" * 60)
            logger.info("Database Connection Test - SUCCESS")
            logger.info("=" * 60)
            logger.info(f"Database: {result.database_name}")
            logger.info(f"SQL Server Version: {result.version[:80]}...")
            logger.info("=" * 60)

            cursor.close()
            return True

        except pyodbc.Error as e:
            logger.error("=" * 60)
            logger.error("Database Connection Test - FAILED")
            logger.error("=" * 60)
            logger.error(f"Error: {e}")
            logger.error("=" * 60)
            return False

    def get_table_info(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get column information for a table.

        Args:
            table_name: Name of the table

        Returns:
            List of dictionaries containing column information
        """
        sql = """
            SELECT
                COLUMN_NAME,
                DATA_TYPE,
                CHARACTER_MAXIMUM_LENGTH,
                IS_NULLABLE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION
        """
        return self.execute_dict(sql, (table_name,))

    def close(self):
        """Close the database connection"""
        if self._connection:
            try:
                self._connection.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            finally:
                self._connection = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False


# Convenience functions for quick access

def get_connection() -> pyodbc.Connection:
    """
    Get a database connection (convenience function).

    Returns:
        pyodbc.Connection: Active database connection
    """
    db = DatabaseConnection()
    return db.get_connection()


def execute_query(sql: str, params: Optional[Tuple] = None) -> List[pyodbc.Row]:
    """
    Execute a query and return results (convenience function).

    Args:
        sql: SQL query string
        params: Optional tuple of parameters

    Returns:
        List of pyodbc.Row objects
    """
    with DatabaseConnection() as db:
        return db.execute_query(sql, params)


def test_connection() -> bool:
    """
    Test database connection (convenience function).

    Returns:
        bool: True if connection successful
    """
    with DatabaseConnection() as db:
        return db.test_connection()


if __name__ == "__main__":
    # Run connection test when module is executed directly
    print("\n" + "=" * 60)
    print("PI Generator - Database Connection Module")
    print("=" * 60 + "\n")

    test_connection()
