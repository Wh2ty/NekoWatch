"""Compatibility shim for aggregation helpers."""

from repositories.sqlalchemy_aggregates import (
    GROUPABLE_COLUMNS,
    SqlAlchemyAggregatesMixin,
)

# Historical name kept so older docs / imports keep working.
SqliteAggregatesMixin = SqlAlchemyAggregatesMixin

__all__ = ["GROUPABLE_COLUMNS", "SqlAlchemyAggregatesMixin", "SqliteAggregatesMixin"]
