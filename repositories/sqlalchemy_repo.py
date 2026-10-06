"""Async SQLAlchemy event store (SQLAlchemy 2.0 + aiosqlite dialect).

Replaces the previous raw-``aiosqlite`` repository. Services still depend on
:class:`~repositories.base.LogRepository`; only this module talks to the ORM.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Sequence

from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from core import mitre as mitre_module
from db.models import (
    Alert,
    AlertMitre,
    CorrelationIncident,
    CorrelationRule,
    IngestState,
    MonitoredSource,
    NetworkUser,
    StatusNotification,
    TriageEventRow,
)
from db.session import Database
from domain.models import LogRecord, TriageStatus
from domain.queries import LogFilter, Pagination, SortOrder, TriageEvent
from repositories.filters import apply_filter
from repositories.mapping import alert_to_record, record_to_alert_values
from repositories.sqlalchemy_aggregates import SqlAlchemyAggregatesMixin

logger = logging.getLogger("nekowatch.repository")


class SqlAlchemyLogRepository(SqlAlchemyAggregatesMixin):
    """Async SQLAlchemy implementation of :class:`~repositories.base.LogRepository`."""

    def __init__(
        self,
        database_path: Path | str | None = None,
        *,
        database: Database | None = None,
        url: str | None = None,
    ) -> None:
        if database is not None:
            self._db = database
        elif url is not None:
            self._db = Database(url)
        elif database_path is not None:
            self._db = Database.from_path(database_path)
        else:
            raise ValueError("database_path_or_url_required")

        self._write_lock = asyncio.Lock()
        self._next_seq: int = 1
        self._fts_enabled: bool = False

    # ------------------------------------------------------------- lifecycle
    @property
    def fts_enabled(self) -> bool:
        """Whether the FTS5 full-text index is available."""
        return self._fts_enabled

    @property
    def database(self) -> Database:
        """Underlying engine/session factory."""
        return self._db

    def _session(self):
        """Session context manager used by the aggregates mixin."""
        return self._db.session()

    async def initialize(self) -> None:
        """Create tables, FTS index and restore the sequence counter."""
        await self._db.initialize()
        self._fts_enabled = self._db.fts_enabled
        async with self._db.session() as session:
            max_seq = await session.scalar(select(func.max(Alert.seq)))
        self._next_seq = int(max_seq or 0) + 1
        logger.info(
            "repository_ready",
            extra={"url": self._db.url, "next_seq": self._next_seq},
        )

    async def close(self) -> None:
        """Dispose the async engine."""
        await self._db.close()

    async def wipe_all(self) -> dict[str, int]:
        """Delete every application row (alerts, status, checkpoints, FTS).

        Returns a map of table name -> deleted row count (best-effort).
        """
        counts: dict[str, int] = {}
        async with self._write_lock:
            async with self._db.session() as session:
                ordered = (
                    ("status_notifications", StatusNotification),
                    ("triage_events", TriageEventRow),
                    ("alert_mitre", AlertMitre),
                    ("alerts", Alert),
                    ("correlation_incidents", CorrelationIncident),
                    ("correlation_rules", CorrelationRule),
                    ("monitored_sources", MonitoredSource),
                    ("network_users", NetworkUser),
                    ("ingest_state", IngestState),
                )
                for name, model in ordered:
                    result = await session.execute(delete(model))
                    counts[name] = int(result.rowcount or 0)

                if self._fts_enabled:
                    try:
                        await session.execute(text("DELETE FROM alerts_fts"))
                        counts["alerts_fts"] = -1
                    except Exception:  # noqa: BLE001 - FTS may be unavailable mid-flight
                        logger.warning("wipe_fts_failed", exc_info=True)

            self._next_seq = 1
        logger.info("repository_wiped", extra={"counts": counts})
        return counts

    # ----------------------------------------------------------------- write
    async def insert_many(
        self,
        records: Sequence[tuple[LogRecord, str]],
        *,
        checkpoints: Sequence[tuple[str, int | None, int]] | None = None,
    ) -> list[LogRecord]:
        """Persist a batch of records (and optional checkpoints) in one TX."""
        if not records and not checkpoints:
            return []

        async with self._write_lock:
            stored: list[LogRecord] = []
            alert_rows: list[dict] = []
            mitre_rows: list[dict] = []
            fts_rows: list[tuple[int, str | None, str | None, str | None]] = []

            for record, raw in records:
                record.seq = self._next_seq
                self._next_seq += 1
                stored.append(record)
                alert_rows.append(record_to_alert_values(record, raw))
                for technique_id in record.mitre_techniques:
                    technique = mitre_module.describe(technique_id)
                    tactic_id = (
                        technique.tactic_id
                        if technique
                        else (
                            record.mitre_tactics[0]
                            if record.mitre_tactics
                            else "unknown"
                        )
                    )
                    mitre_rows.append(
                        {
                            "seq": record.seq,
                            "tactic_id": tactic_id,
                            "technique_id": technique_id,
                        }
                    )
                if self._fts_enabled:
                    fts_rows.append(
                        (record.seq, record.message, record.rule_description, raw)
                    )

            async with self._db.session() as session:
                if alert_rows:
                    await session.execute(insert(Alert), alert_rows)
                if mitre_rows:
                    await session.execute(insert(AlertMitre), mitre_rows)
                if fts_rows:
                    await session.execute(
                        text(
                            "INSERT INTO alerts_fts "
                            "(rowid, message, rule_description, raw) "
                            "VALUES (:seq, :message, :rule_description, :raw)"
                        ),
                        [
                            {
                                "seq": seq,
                                "message": message,
                                "rule_description": description,
                                "raw": raw,
                            }
                            for seq, message, description, raw in fts_rows
                        ],
                    )
                if checkpoints:
                    now = datetime.now(timezone.utc).isoformat()
                    for path, inode, offset in checkpoints:
                        stmt = sqlite_insert(IngestState).values(
                            path=path,
                            inode=inode,
                            byte_offset=offset,
                            updated_at=now,
                        )
                        stmt = stmt.on_conflict_do_update(
                            index_elements=[IngestState.path],
                            set_={
                                "inode": stmt.excluded.inode,
                                "byte_offset": stmt.excluded.byte_offset,
                                "updated_at": stmt.excluded.updated_at,
                            },
                        )
                        await session.execute(stmt)
            return stored

    async def prune(self, max_events: int) -> int:
        """Delete the oldest events so at most ``max_events`` remain."""
        if max_events <= 0:
            return 0
        async with self._write_lock:
            async with self._db.session() as session:
                total = int(
                    await session.scalar(select(func.count()).select_from(Alert)) or 0
                )
                excess = total - max_events
                if excess <= 0:
                    return 0

                victims = (
                    await session.execute(
                        select(
                            Alert.seq, Alert.message, Alert.rule_description, Alert.raw
                        )
                        .order_by(Alert.seq.asc())
                        .limit(excess)
                    )
                ).all()
                seqs = [int(row.seq) for row in victims]
                if not seqs:
                    return 0

                if self._fts_enabled:
                    await session.execute(
                        text(
                            "INSERT INTO alerts_fts "
                            "(alerts_fts, rowid, message, rule_description, raw) "
                            "VALUES ('delete', :seq, :message, :rule_description, :raw)"
                        ),
                        [
                            {
                                "seq": row.seq,
                                "message": row.message,
                                "rule_description": row.rule_description,
                                "raw": row.raw,
                            }
                            for row in victims
                        ],
                    )

                await session.execute(
                    delete(AlertMitre).where(AlertMitre.seq.in_(seqs))
                )
                await session.execute(
                    delete(TriageEventRow).where(TriageEventRow.seq.in_(seqs))
                )
                await session.execute(delete(Alert).where(Alert.seq.in_(seqs)))
                logger.info("pruned_events", extra={"removed": len(seqs)})
                return len(seqs)

    # ------------------------------------------------------------------ read
    async def count(self, log_filter: LogFilter) -> int:
        stmt = apply_filter(
            select(func.count()).select_from(Alert),
            log_filter,
            fts_enabled=self._fts_enabled,
        )
        async with self._db.session() as session:
            return int(await session.scalar(stmt) or 0)

    async def search(
        self, log_filter: LogFilter, pagination: Pagination
    ) -> list[LogRecord]:
        direction = (
            Alert.ts_epoch.asc()
            if pagination.order is SortOrder.ASC
            else Alert.ts_epoch.desc()
        )
        seq_dir = (
            Alert.seq.asc() if pagination.order is SortOrder.ASC else Alert.seq.desc()
        )
        stmt = (
            apply_filter(select(Alert), log_filter, fts_enabled=self._fts_enabled)
            .order_by(direction, seq_dir)
            .limit(pagination.limit)
            .offset(pagination.offset)
        )
        async with self._db.session() as session:
            rows = (await session.scalars(stmt)).all()
        return [alert_to_record(row) for row in rows]

    async def get(self, seq: int) -> tuple[LogRecord, str | None] | None:
        async with self._db.session() as session:
            row = await session.get(Alert, seq)
            if row is None:
                return None
            return alert_to_record(row), row.raw

    async def iter_records(
        self,
        log_filter: LogFilter,
        *,
        chunk_size: int = 1_000,
        max_rows: int = 0,
        ascending: bool = True,
    ) -> AsyncIterator[LogRecord]:
        cursor_value: int | None = None
        emitted = 0

        while True:
            batch = chunk_size
            if max_rows:
                batch = min(batch, max_rows - emitted)
                if batch <= 0:
                    return

            stmt = apply_filter(
                select(Alert), log_filter, fts_enabled=self._fts_enabled
            )
            if cursor_value is not None:
                stmt = stmt.where(
                    Alert.seq > cursor_value if ascending else Alert.seq < cursor_value
                )
            stmt = stmt.order_by(
                Alert.seq.asc() if ascending else Alert.seq.desc()
            ).limit(batch)

            async with self._db.session() as session:
                rows = list((await session.scalars(stmt)).all())
            if not rows:
                return

            for row in rows:
                yield alert_to_record(row)
                emitted += 1
            cursor_value = int(rows[-1].seq)
            if len(rows) < batch:
                return

    async def stored_count(self) -> int:
        async with self._db.session() as session:
            return int(
                await session.scalar(select(func.count()).select_from(Alert)) or 0
            )

    async def last_event_at(self) -> datetime | None:
        async with self._db.session() as session:
            newest = await session.scalar(select(func.max(Alert.ts_epoch)))
        if newest is None:
            return None
        return datetime.fromtimestamp(float(newest), tz=timezone.utc)

    # ---------------------------------------------------------------- triage
    async def set_triage(
        self,
        seqs: Sequence[int],
        status: TriageStatus,
        analyst: str | None = None,
        note: str | None = None,
    ) -> int:
        unique = [int(s) for s in dict.fromkeys(seqs)]
        if not unique:
            return 0

        status = TriageStatus(status)
        now = datetime.now(timezone.utc).isoformat()

        async with self._write_lock:
            async with self._db.session() as session:
                previous = (
                    await session.execute(
                        select(Alert.seq, Alert.triage_status).where(
                            Alert.seq.in_(unique)
                        )
                    )
                ).all()
                if not previous:
                    return 0

                await session.execute(
                    update(Alert)
                    .where(Alert.seq.in_(unique))
                    .values(
                        triage_status=status.value,
                        triage_analyst=analyst,
                        triage_note=note,
                        triage_updated_at=now,
                    )
                )
                session.add_all(
                    [
                        TriageEventRow(
                            seq=int(row.seq),
                            status=status.value,
                            previous_status=row.triage_status,
                            analyst=analyst,
                            note=note,
                            created_at=now,
                        )
                        for row in previous
                    ]
                )
                return len(previous)

    async def triage_history(self, seq: int) -> list[TriageEvent]:
        async with self._db.session() as session:
            rows = (
                await session.scalars(
                    select(TriageEventRow)
                    .where(TriageEventRow.seq == seq)
                    .order_by(TriageEventRow.id.asc())
                )
            ).all()
        return [
            TriageEvent(
                id=int(row.id),
                seq=int(row.seq),
                status=TriageStatus(row.status),
                previous_status=(
                    TriageStatus(row.previous_status) if row.previous_status else None
                ),
                analyst=row.analyst,
                note=row.note,
                created_at=datetime.fromisoformat(row.created_at),
            )
            for row in rows
        ]

    # ---------------------------------------------------------- ingest state
    async def save_ingest_state(
        self, path: str, inode: int | None, offset: int
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        stmt = sqlite_insert(IngestState).values(
            path=path, inode=inode, byte_offset=offset, updated_at=now
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[IngestState.path],
            set_={
                "inode": stmt.excluded.inode,
                "byte_offset": stmt.excluded.byte_offset,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        async with self._write_lock:
            async with self._db.session() as session:
                await session.execute(stmt)

    async def load_ingest_state(self, path: str) -> tuple[int | None, int] | None:
        async with self._db.session() as session:
            row = await session.get(IngestState, path)
            if row is None:
                return None
            inode = int(row.inode) if row.inode is not None else None
            return inode, int(row.byte_offset)


# Backwards-compatible alias used by older imports / docs.
SqliteLogRepository = SqlAlchemyLogRepository
