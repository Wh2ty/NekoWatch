"""Storage contract for the analyzer.

Services depend on this ``Protocol`` rather than on SQLite, so the event store
can be swapped for Elasticsearch/OpenSearch or Postgres without touching
business logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import AsyncIterator, Protocol, Sequence

from domain.models import LogRecord, TriageStatus
from domain.queries import (
    CorrelationGroup,
    FieldCount,
    IpCount,
    LogFilter,
    MitreBreakdown,
    OverviewResponse,
    Pagination,
    RuleCount,
    SeverityCount,
    TimelinePoint,
    TriageEvent,
    TriageSummary,
)


class LogRepository(Protocol):
    """Persistence and aggregation operations required by the services."""

    # ------------------------------------------------------------- lifecycle
    async def initialize(self) -> None:
        """Open the store and apply the schema."""
        ...

    async def close(self) -> None:
        """Release the underlying connection."""
        ...

    # ----------------------------------------------------------------- write
    async def insert_many(
        self,
        records: Sequence[tuple[LogRecord, str]],
        *,
        checkpoints: Sequence[tuple[str, int | None, int]] | None = None,
    ) -> list[LogRecord]:
        """Persist a batch of ``(record, raw_line)`` pairs, assigning ``seq``.

        Optional ``checkpoints`` are ``(path, inode, offset)`` rows written in
        the same transaction so a crash cannot lose the batch after advancing
        the file cursor.
        """
        ...

    async def prune(self, max_events: int) -> int:
        """Delete the oldest events beyond ``max_events``; return rows removed."""
        ...

    # ------------------------------------------------------------------ read
    async def count(self, log_filter: LogFilter) -> int:
        """Number of events matching the filter."""
        ...

    async def search(
        self, log_filter: LogFilter, pagination: Pagination
    ) -> list[LogRecord]:
        """One page of matching events."""
        ...

    async def get(self, seq: int) -> tuple[LogRecord, str | None] | None:
        """Fetch a single event and its original raw line."""
        ...

    async def iter_records(
        self,
        log_filter: LogFilter,
        *,
        chunk_size: int = 1_000,
        max_rows: int = 0,
        ascending: bool = True,
    ) -> AsyncIterator[LogRecord]:
        """Stream matching events using keyset pagination (constant memory)."""
        ...

    async def stored_count(self) -> int:
        """Total number of stored events, ignoring filters."""
        ...

    async def last_event_at(self) -> datetime | None:
        """Timestamp of the most recent stored event."""
        ...

    # ------------------------------------------------------------ aggregates
    async def timeline(
        self, log_filter: LogFilter, interval_seconds: int
    ) -> list[TimelinePoint]:
        """Events-over-time histogram, bucketed by ``interval_seconds``."""
        ...

    async def severity_distribution(
        self, log_filter: LogFilter
    ) -> list[SeverityCount]:
        """Event counts per severity bucket."""
        ...

    async def top_rules(
        self, log_filter: LogFilter, limit: int = 10
    ) -> list[RuleCount]:
        """Most frequently triggered rules."""
        ...

    async def top_ips(
        self, log_filter: LogFilter, column: str, limit: int = 10
    ) -> list[IpCount]:
        """Most frequent source or destination addresses."""
        ...

    async def top_field(
        self, log_filter: LogFilter, column: str, limit: int = 10
    ) -> list[FieldCount]:
        """Generic ``top N`` aggregation over an allow-listed column."""
        ...

    async def mitre_breakdown(
        self, log_filter: LogFilter, limit: int = 20
    ) -> MitreBreakdown:
        """ATT&CK tactic/technique counts for the selection."""
        ...

    async def overview(self, log_filter: LogFilter) -> OverviewResponse:
        """Headline KPIs for the selection."""
        ...

    async def group_events(
        self,
        log_filter: LogFilter,
        group_by: Sequence[str],
        *,
        min_count: int = 2,
        limit: int = 25,
    ) -> list[CorrelationGroup]:
        """Collapse similar events into signature groups."""
        ...

    # ---------------------------------------------------------------- triage
    async def set_triage(
        self,
        seqs: Sequence[int],
        status: TriageStatus,
        analyst: str | None = None,
        note: str | None = None,
    ) -> int:
        """Apply a triage state to the given events; return rows updated."""
        ...

    async def triage_summary(self) -> TriageSummary:
        """Queue counters for the triage board."""
        ...

    async def triage_history(self, seq: int) -> list[TriageEvent]:
        """Audit trail for one event, oldest first."""
        ...

    # ---------------------------------------------------------- ingest state
    async def save_ingest_state(self, path: str, inode: int | None, offset: int) -> None:
        """Checkpoint the tail position so restarts resume without replaying."""
        ...

    async def load_ingest_state(self, path: str) -> tuple[int | None, int] | None:
        """Load a previously saved ``(inode, offset)`` checkpoint."""
        ...
