"""Compatibility shim — the store is now Async SQLAlchemy.

Import :class:`~repositories.sqlalchemy_repo.SqlAlchemyLogRepository`
(aliased here as ``SqliteLogRepository``) from this module or from
``repositories.sqlalchemy_repo``.
"""

from repositories.sqlalchemy_repo import SqlAlchemyLogRepository, SqliteLogRepository

__all__ = ["SqlAlchemyLogRepository", "SqliteLogRepository"]
