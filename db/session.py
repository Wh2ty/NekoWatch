"""Async engine and session factory (SQLAlchemy 2.0 + aiosqlite)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from db.base import Base

logger = logging.getLogger("nekowatch.db")

_FTS_DDL = """
CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts USING fts5(
    message,
    rule_description,
    raw,
    content='alerts',
    content_rowid='seq'
)
"""


def database_url(path: Path | str) -> str:
    """Build a ``sqlite+aiosqlite`` URL for a filesystem path or ``:memory:``."""
    raw = str(path)
    if raw in {":memory:", "sqlite+aiosqlite:///:memory:"}:
        return "sqlite+aiosqlite:///:memory:"
    resolved = Path(raw).expanduser()
    if not resolved.is_absolute():
        resolved = resolved.resolve()
    return f"sqlite+aiosqlite:///{resolved}"


def create_engine(url: str, *, echo: bool = False) -> AsyncEngine:
    """Create the async engine with SQLite-friendly pooling defaults."""
    connect_args: dict = {"check_same_thread": False}
    # StaticPool keeps a single :memory: connection shared across sessions.
    kwargs: dict = {"echo": echo, "connect_args": connect_args}
    if url.endswith(":memory:"):
        from sqlalchemy.pool import StaticPool

        kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True

    engine = create_async_engine(url, **kwargs)

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn, _connection_record) -> None:  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


class Database:
    """Owns the async engine/sessionmaker and schema bootstrap."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        self.engine: AsyncEngine = create_engine(url, echo=echo)
        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self.fts_enabled: bool = False

    @classmethod
    def from_path(cls, path: Path | str, *, echo: bool = False) -> "Database":
        """Construct from a SQLite filesystem path."""
        resolved = Path(path)
        if str(path) not in {":memory:", "sqlite+aiosqlite:///:memory:"}:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        return cls(database_url(path), echo=echo)

    async def initialize(self) -> None:
        """Create ORM tables and the optional FTS5 virtual table."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            try:
                await conn.execute(text(_FTS_DDL))
                self.fts_enabled = True
            except Exception:  # noqa: BLE001 - FTS5 is optional
                self.fts_enabled = False
                logger.warning("fts5_unavailable_falling_back_to_like")
        logger.info(
            "database_ready",
            extra={"url": self.url, "fts": self.fts_enabled},
        )

    async def close(self) -> None:
        """Dispose the engine and release pooled connections."""
        await self.engine.dispose()
        logger.info("database_closed")

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a short-lived session that commits on success."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
