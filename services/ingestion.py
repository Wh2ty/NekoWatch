"""Non-blocking ingestion pipeline: tail -> parse -> batch-store -> fan out.

Supports one or more alert files declared in ``config/sources.yaml`` (real
Wazuh paths or the Logener demo file). Each path gets its own tail task and
checkpoint; a shared writer drains a bounded queue into SQLite batches.

Backpressure is intentional: when the writer falls behind, ``queue.put``
suspends the tail loop. The file on disk is the buffer, so slowing down is
lossless — unlike dropping events to keep up.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

import aiofiles

from core.config import Settings
from core.sources_config import LogSource, load_sources_config
from domain.models import LogRecord
from domain.queries import IngestAcceptResult, IngestionStatus, SourceIngestStatus
from domain.stream import StreamStats
from repositories.base import LogRepository
from services.eps_meter import EpsMeter
from services.live import LiveHub
from services.parser import AlertParser, PlainAlertAssembler

if TYPE_CHECKING:
    from services.rule_engine import RuleEngine
    from services.status_monitor import StatusMonitorService

logger = logging.getLogger("nekowatch.ingestion")

#: Instantaneous EPS window: events accepted in the last second (in-memory).
_EPS_WINDOW = 1.0
#: How often the optional stored-count cache is refreshed (not on the EPS path).
_STORED_CACHE_INTERVAL = 30.0


@dataclass(slots=True)
class _QueuedEvent:
    """A parsed record awaiting persistence, tagged with its file offset."""

    record: LogRecord
    raw: str
    offset: int
    path: str
    inode: int | None
    enqueued_at: float = 0.0


@dataclass
class _FileCursor:
    """Per-source read position and optional plain-text assembler."""

    source: LogSource
    inode: int | None = None
    offset: int = 0
    assembler: PlainAlertAssembler = field(default_factory=PlainAlertAssembler)


class IngestionService:
    """Owns the tail/parse/store pipeline for one or more alert files."""

    def __init__(
        self,
        settings: Settings,
        repository: LogRepository,
        hub: LiveHub,
        parser: AlertParser | None = None,
        status_monitor: StatusMonitorService | None = None,
        rule_engine: RuleEngine | None = None,
        sources: list[LogSource] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._hub = hub
        self._parser = parser or AlertParser()
        self._status_monitor = status_monitor
        self._rule_engine = rule_engine

        resolved = sources if sources is not None else self._resolve_sources(settings)
        if not resolved:
            resolved = [
                LogSource(
                    name="default",
                    path=Path(settings.log_file),
                    format="ndjson",
                    description="NEKOWATCH_LOG_FILE fallback",
                )
            ]
        self._sources = resolved
        self._cursors: dict[str, _FileCursor] = {
            str(src.path): _FileCursor(source=src) for src in resolved
        }
        self._primary_path = Path(resolved[0].path)

        self._queue: asyncio.Queue[_QueuedEvent] = asyncio.Queue(
            maxsize=settings.ingest_queue_size
        )
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()

        self._ingested: int = 0
        self._batches: int = 0
        self._eps = EpsMeter(window_seconds=_EPS_WINDOW)
        self._stored_cache: int = 0
        self._last_stored_refresh: float = 0.0
        self._last_event_at: float | None = None
        # Coalesced JSON-arrival fan-out (never waits on SQL).
        self._json_push_pending: int = 0
        self._json_push_task: asyncio.Task[None] | None = None
        self._json_push_interval: float = 0.2
        # Synthetic byte-offsets for non-file producers (HTTP push / API poll).
        self._api_offsets: dict[str, int] = {}

    @staticmethod
    def _resolve_sources(settings: Settings) -> list[LogSource]:
        config_path = Path(settings.sources_config)
        loaded = load_sources_config(config_path)
        if loaded:
            return loaded
        return [
            LogSource(
                name="default",
                path=Path(settings.log_file),
                format="ndjson",
                description="NEKOWATCH_LOG_FILE fallback",
            )
        ]

    # ------------------------------------------------------------- properties
    @property
    def parser(self) -> AlertParser:
        """The parser instance (exposes parse-error counters)."""
        return self._parser

    @property
    def running(self) -> bool:
        """Whether the pipeline tasks are alive."""
        return bool(self._tasks) and not self._stopping.is_set()

    @property
    def sources(self) -> list[LogSource]:
        """Active log sources being tailed."""
        return list(self._sources)

    @property
    def primary_path(self) -> Path:
        """First active source path (used by Logener / status compatibility)."""
        return self._primary_path

    def current_eps(self) -> float:
        """Trailing events-per-second over the last second (in-memory)."""
        return self._eps.snapshot().events_per_second

    def eps_snapshot(self) -> tuple[float, int]:
        """Return ``(events_per_second, events_in_window)`` for the trailing 1s."""
        snap = self._eps.snapshot()
        return snap.events_per_second, snap.events_in_window
    # -------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        """Resume from stored checkpoints and launch the pipeline tasks."""
        for cursor in self._cursors.values():
            cursor.source.path.parent.mkdir(parents=True, exist_ok=True)
            await self._restore_position(cursor)

        self._stopping.clear()
        self._tasks = [
            asyncio.create_task(
                self._tail_loop(cursor),
                name=f"nekowatch-tail-{cursor.source.name}",
            )
            for cursor in self._cursors.values()
        ]
        self._tasks.append(
            asyncio.create_task(self._writer_loop(), name="nekowatch-writer")
        )
        self._tasks.append(
            asyncio.create_task(
                self._maintenance_loop(), name="nekowatch-maintenance"
            )
        )
        logger.info(
            "ingestion_started",
            extra={
                "sources": [
                    {"name": s.name, "path": str(s.path), "format": s.format}
                    for s in self._sources
                ],
            },
        )

    async def stop(self) -> None:
        """Stop tailing, flush what is already queued, then cancel tasks."""
        if not self._tasks:
            return
        self._stopping.set()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._drain(), timeout=5.0)
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for cursor in self._cursors.values():
            await self._repository.save_ingest_state(
                str(cursor.source.path), cursor.inode, cursor.offset
            )
        logger.info(
            "ingestion_stopped",
            extra={"ingested": self._ingested},
        )

    async def _restore_position(self, cursor: _FileCursor) -> None:
        """Decide where to start reading for one source."""
        path = cursor.source.path
        stat = self._stat(path)
        state = await self._repository.load_ingest_state(str(path))

        if stat is None:
            cursor.inode = None
            cursor.offset = 0
            return

        if state is not None:
            saved_inode, saved_offset = state
            if saved_inode == stat.st_ino and saved_offset <= stat.st_size:
                cursor.inode, cursor.offset = stat.st_ino, saved_offset
                return

        cursor.inode = stat.st_ino
        cursor.offset = 0 if self._settings.ingest_from_start else stat.st_size

    @staticmethod
    def _stat(path: Path) -> os.stat_result | None:
        """``os.stat`` a path, tolerating its absence."""
        try:
            return os.stat(path)
        except OSError:
            return None

    async def _drain(self) -> None:
        """Wait until the queue is empty (used during shutdown)."""
        while not self._queue.empty():
            await asyncio.sleep(0.05)

    # -------------------------------------------------------------- tail loop
    async def _tail_loop(self, cursor: _FileCursor) -> None:
        """Follow one alert file and enqueue parsed records."""
        while not self._stopping.is_set():
            try:
                if self._stat(cursor.source.path) is None:
                    await asyncio.sleep(self._settings.tail_poll_interval)
                    continue
                await self._follow_once(cursor)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - keep tailing despite I/O errors
                logger.exception(
                    "tail_loop_error",
                    extra={"source": cursor.source.name},
                )
                await asyncio.sleep(1.0)

    async def _follow_once(self, cursor: _FileCursor) -> None:
        """Read from the current offset until rotation is detected."""
        path = cursor.source.path
        async with aiofiles.open(
            path, "r", encoding="utf-8", errors="replace"
        ) as handle:
            await handle.seek(cursor.offset)

            while not self._stopping.is_set():
                position = await handle.tell()
                line = await handle.readline()

                if not line:
                    cursor.offset = position
                    if self._rotated(cursor):
                        return
                    await asyncio.sleep(self._settings.tail_poll_interval)
                    continue

                if not line.endswith("\n"):
                    # The writer is mid-line; rewind and wait for the rest.
                    await handle.seek(position)
                    cursor.offset = position
                    await asyncio.sleep(self._settings.tail_poll_interval)
                    continue

                offset_after = await handle.tell()
                if cursor.source.format == "plain":
                    blocks = cursor.assembler.feed(line)
                    for block in blocks:
                        await self._enqueue_parsed(
                            cursor, block, offset_after, format="plain"
                        )
                    cursor.offset = offset_after
                    continue

                await self._enqueue_parsed(
                    cursor, line, offset_after, format="ndjson"
                )
                # Offset advances even for skipped lines so we do not re-read.
                cursor.offset = offset_after

    async def _enqueue_parsed(
        self,
        cursor: _FileCursor,
        text: str,
        offset_after: int,
        *,
        format: str,
    ) -> None:
        parsed = self._parser.parse_line(text, format=format)
        if parsed is None:
            return
        record, raw = parsed
        await self._enqueue_record(
            record,
            raw,
            path=str(cursor.source.path),
            offset=offset_after,
            inode=cursor.inode,
        )

    async def _enqueue_record(
        self,
        record: LogRecord,
        raw: str,
        *,
        path: str,
        offset: int,
        inode: int | None = None,
    ) -> None:
        """Put one normalized event on the writer queue and update live EPS."""
        arrived = time.monotonic()
        self._eps.observe(1, at=arrived)
        self._schedule_json_arrival_push()
        await self._queue.put(
            _QueuedEvent(
                record=record,
                raw=raw,
                offset=offset,
                path=path,
                inode=inode,
                enqueued_at=arrived,
            )
        )

    async def accept_payloads(
        self,
        payloads: Iterable[str | dict[str, Any]],
        *,
        source_key: str = "api:push",
        format: str = "ndjson",
    ) -> IngestAcceptResult:
        """Accept Wazuh alerts from an HTTP push or API poller.

        Payloads are parsed with the same :class:`AlertParser` as file tails,
        then fed into the shared queue so LiveHub / rules / status stay in sync.
        """
        accepted = 0
        skipped = 0
        path = source_key if source_key.startswith("api:") else f"api:{source_key}"
        offset = self._api_offsets.get(path, 0)

        for item in payloads:
            if isinstance(item, dict):
                text = json.dumps(item, ensure_ascii=False)
            else:
                text = str(item).strip()
                if not text:
                    skipped += 1
                    continue
            parsed = self._parser.parse_line(text, format=format)
            if parsed is None:
                skipped += 1
                continue
            record, raw = parsed
            offset += 1
            await self._enqueue_record(
                record, raw, path=path, offset=offset, inode=None
            )
            accepted += 1

        self._api_offsets[path] = offset
        return IngestAcceptResult(
            accepted=accepted,
            skipped=skipped,
            source=path,
            queue_depth=self._queue.qsize(),
        )

    def _schedule_json_arrival_push(self) -> None:
        """Queue a coalesced WebSocket tick for the JSON EPS chart."""
        self._json_push_pending += 1
        if self._json_push_task is not None and not self._json_push_task.done():
            return
        self._json_push_task = asyncio.create_task(
            self._flush_json_arrivals(),
            name="nekowatch-json-eps",
        )

    async def _flush_json_arrivals(self) -> None:
        """Emit pending JSON arrivals without touching SQL."""
        try:
            await asyncio.sleep(self._json_push_interval)
            pending = self._json_push_pending
            self._json_push_pending = 0
            if pending <= 0 or self._stopping.is_set():
                return
            snap = self._eps.snapshot()
            await self._hub.broadcast_json_arrival(
                count=pending,
                events_last_window=snap.events_in_window,
                events_per_second=snap.events_per_second,
                sample_epoch=time.time(),
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - chart must not break ingest
            logger.exception("json_arrival_push_failed")

    def _rotated(self, cursor: _FileCursor) -> bool:
        """Detect log rotation or truncation and reset the read position."""
        path = cursor.source.path
        stat = self._stat(path)
        if stat is None:
            cursor.inode, cursor.offset = None, 0
            cursor.assembler = PlainAlertAssembler()
            return True
        if cursor.inode is not None and stat.st_ino != cursor.inode:
            logger.info(
                "log_rotation_detected",
                extra={
                    "source": cursor.source.name,
                    "old_inode": cursor.inode,
                    "new_inode": stat.st_ino,
                },
            )
            cursor.inode, cursor.offset = stat.st_ino, 0
            cursor.assembler = PlainAlertAssembler()
            return True
        if stat.st_size < cursor.offset:
            logger.info(
                "log_truncation_detected",
                extra={
                    "source": cursor.source.name,
                    "size": stat.st_size,
                    "offset": cursor.offset,
                },
            )
            cursor.offset = 0
            cursor.assembler = PlainAlertAssembler()
            return True
        if cursor.inode is None:
            cursor.inode = stat.st_ino
        return False

    # ------------------------------------------------------------ writer loop
    async def _writer_loop(self) -> None:
        """Batch queued records into the store and fan them out."""
        while not self._stopping.is_set() or not self._queue.empty():
            try:
                batch = await self._collect_batch()
                if not batch:
                    continue
                await self._persist(batch)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a bad batch must not kill ingest
                logger.exception("writer_loop_error")
                await asyncio.sleep(0.5)

    async def _collect_batch(self) -> list[_QueuedEvent]:
        """Gather up to ``ingest_batch_size`` events, bounded by a flush timer."""
        try:
            first = await asyncio.wait_for(
                self._queue.get(), timeout=self._settings.ingest_flush_interval
            )
        except asyncio.TimeoutError:
            return []

        batch = [first]
        while len(batch) < self._settings.ingest_batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def _persist(self, batch: list[_QueuedEvent]) -> None:
        """Commit a batch with per-path checkpoints, then publish."""
        checkpoints: list[tuple[str, int | None, int]] = []
        by_path: dict[str, list[_QueuedEvent]] = defaultdict(list)
        for item in batch:
            by_path[item.path].append(item)
        for path, items in by_path.items():
            checkpoint = max(item.offset for item in items)
            inode = next(
                (item.inode for item in reversed(items) if item.inode is not None),
                None,
            )
            checkpoints.append((path, inode, checkpoint))
            cursor = self._cursors.get(path)
            if cursor is not None:
                cursor.offset = max(cursor.offset, checkpoint)
                if inode is not None:
                    cursor.inode = inode

        stored = await self._repository.insert_many(
            [(item.record, item.raw) for item in batch],
            checkpoints=checkpoints,
        )
        self._batches += 1
        self._ingested += len(stored)
        self._stored_cache = max(self._stored_cache, self._ingested)
        self._last_event_at = time.time()

        await self._hub.publish_records(stored)

        if self._status_monitor is not None and stored:
            try:
                await self._status_monitor.touch_from_records(stored)
            except Exception:  # noqa: BLE001 - status must not block ingest
                logger.exception("status_heartbeat_failed")

        if self._rule_engine is not None and stored:
            try:
                await self._rule_engine.evaluate_records(stored)
            except Exception:  # noqa: BLE001 - rules must not block ingest
                logger.exception("rule_engine_failed")

    # ------------------------------------------------------- maintenance loop
    async def _maintenance_loop(self) -> None:
        """Broadcast SQL-free telemetry and apply the retention policy."""
        last_prune = time.monotonic()
        while not self._stopping.is_set():
            await asyncio.sleep(self._settings.live_stats_interval)
            try:
                # Hot path: EPS + queue depth from memory only.
                await self._hub.broadcast_stats(self.live_stats())

                now = time.monotonic()
                if now - self._last_stored_refresh >= _STORED_CACHE_INTERVAL:
                    self._last_stored_refresh = now
                    try:
                        self._stored_cache = await self._repository.stored_count()
                    except Exception:  # noqa: BLE001
                        logger.exception("stored_count_cache_refresh_failed")

                if (
                    self._settings.retention_max_events > 0
                    and now - last_prune >= self._settings.retention_interval
                ):
                    last_prune = now
                    await self._repository.prune(self._settings.retention_max_events)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("maintenance_loop_error")

    # ------------------------------------------------------------- reporting
    def live_stats(self) -> StreamStats:
        """In-memory telemetry for WebSocket clients — never touches SQL."""
        snap = self._eps.snapshot()
        return StreamStats(
            events_per_second=snap.events_per_second,
            events_last_window=snap.events_in_window,
            eps_window_seconds=snap.window_seconds,
            sample_epoch=time.time(),
            ingested=self._ingested,
            stored_events=self._stored_cache,
            queue_depth=self._queue.qsize(),
            parse_errors=self._parser.errors,
            clients=self._hub.client_count,
            dropped_frames=self._hub.dropped_frames,
            eps_sql_free=True,
        )

    async def stats(self) -> StreamStats:
        """Telemetry snapshot (live path + optional fresh stored count)."""
        return self.live_stats()

    async def status(self) -> IngestionStatus:
        """Full pipeline status for the ``/api/v1/ingestion/status`` endpoint."""
        primary = self._cursors[str(self._primary_path)]
        stat = self._stat(self._primary_path)
        rate, count = self.eps_snapshot()
        sources: list[SourceIngestStatus] = []
        for cursor in self._cursors.values():
            s = self._stat(cursor.source.path)
            sources.append(
                SourceIngestStatus(
                    name=cursor.source.name,
                    path=str(cursor.source.path),
                    format=cursor.source.format,
                    file_exists=s is not None,
                    file_size=s.st_size if s else 0,
                    inode=cursor.inode,
                    offset=cursor.offset,
                )
            )
        return IngestionStatus(
            running=self.running,
            log_file=str(self._primary_path),
            file_exists=stat is not None,
            file_size=stat.st_size if stat else 0,
            inode=primary.inode,
            offset=primary.offset,
            ingested=self._ingested,
            parse_errors=self._parser.errors,
            queue_depth=self._queue.qsize(),
            queue_capacity=self._settings.ingest_queue_size,
            batches_written=self._batches,
            events_per_second=rate,
            events_last_window=count,
            eps_window_seconds=_EPS_WINDOW,
            stored_events=await self._repository.stored_count(),
            last_event_at=(
                datetime.fromtimestamp(self._last_event_at, tz=timezone.utc)
                if self._last_event_at
                else None
            ),
            live_clients=self._hub.client_count,
            sources=sources,
        )

    async def reset_after_wipe(self) -> None:
        """Clear in-memory counters/queue and re-point tails at empty files."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._ingested = 0
        self._batches = 0
        self._eps.reset()
        self._stored_cache = 0
        self._last_stored_refresh = 0.0
        self._last_event_at = None
        self._json_push_pending = 0
        if self._json_push_task is not None and not self._json_push_task.done():
            self._json_push_task.cancel()
        self._json_push_task = None
        self._parser.reset()

        for cursor in self._cursors.values():
            path = cursor.source.path
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch()
            stat = self._stat(path)
            cursor.inode = stat.st_ino if stat else None
            cursor.offset = 0
            cursor.assembler = PlainAlertAssembler()
            await self._repository.save_ingest_state(
                str(path), cursor.inode, cursor.offset
            )
        logger.info(
            "ingestion_reset_after_wipe",
            extra={"paths": [str(s.path) for s in self._sources]},
        )
