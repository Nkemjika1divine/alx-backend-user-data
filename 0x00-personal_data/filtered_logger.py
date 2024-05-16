#!/usr/bin/env python3
"""module for the function filter_datum"""
import re
from typing import List
import logging
import os
from mysql.connector import (connection)

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str],
        redaction: str, message: str,
        separator: str) -> str:
    """returns the log message cut out"""
    for field in fields:
        pattern = re.compile(fr'{re.escape(field)}=.*?{re.escape(separator)}')
        replacement = f'{field}={redaction}{separator}'
        cutout_message = re.sub(pattern, replacement, message)
    return cutout_message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initializes the RedactingFormatter"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a log record, redacting specified fields."""
        record.msg = filter_datum(self.fields, self.REDACTION,
                record.msg, self.SEPARATOR)
        return super().format(record)


