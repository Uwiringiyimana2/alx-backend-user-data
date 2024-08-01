#!/usr/bin/env python3
"""Filter Data"""
import re
import logging
import os
import mysql.connector
from typing import Tuple


# Define the fields considered PII
PII_FIELDS: Tuple = ("name", "email", "phone", "ssn", "ip")


def filter_datum(fields, redaction, message, separator):
    """Returns the log message obfuscated."""
    pattern = f"({'|'.join(fields)})=([^;]+)"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        """Initialize the formatter with the specified fields to redact."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record and redact sensitive fields."""
        format_record = super().format(record)
        return filter_datum(self.fields, RedactingFormatter.REDACTION,
                            format_record, RedactingFormatter.SEPARATOR)


def get_logger() -> logging.Logger:
    """Returns a logging.Logger object."""
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """eturns a connector to the database"""
    PERSONAL_DATA_DB_USERNAME = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    PERSONAL_DATA_DB_PASSWORD = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    PERSONAL_DATA_DB_HOST = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    PERSONAL_DATA_DB_NAME = os.getenv('PERSONAL_DATA_DB_NAME')

    return mysql.connector.connect(
        host=PERSONAL_DATA_DB_HOST,
        user=PERSONAL_DATA_DB_USERNAME,
        password=PERSONAL_DATA_DB_PASSWORD,
        database=PERSONAL_DATA_DB_NAME
    )
