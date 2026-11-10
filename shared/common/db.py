"""Database connections. SQLAlchemy Core with explicit SQL, one engine per database URL.

Each request gets a connection inside a transaction: commit on success, rollback on any
error, so multi-step writes (e.g. consume nonce + store ballot) are all-or-nothing.
"""
from collections.abc import Callable, Iterator
from functools import lru_cache

from sqlalchemy import Connection, Engine, create_engine


@lru_cache
def get_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)


def transaction_dependency(url_getter: Callable[[], str | None]) -> Callable[[], Iterator[Connection]]:
    """Build a FastAPI dependency yielding a transactional connection for one database."""

    def dependency() -> Iterator[Connection]:
        url = url_getter()
        if not url:
            raise RuntimeError("Database URL is not configured for this service")
        with get_engine(url).begin() as conn:
            yield conn

    return dependency
