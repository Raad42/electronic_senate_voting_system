"""Small database helpers used by the vertical-slice services."""

from contextlib import contextmanager
import os
from collections.abc import Iterator

import psycopg


@contextmanager
def connection(variable: str) -> Iterator[psycopg.Connection]:
    dsn = os.environ.get(variable)
    if not dsn:
        raise RuntimeError(f"{variable} is not configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        yield conn
