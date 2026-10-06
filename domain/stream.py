"""Envelopes for the live WebSocket feed."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from domain.models import LogRecord


class StreamMessageType(StrEnum):
    """Kinds of frame the server pushes to a live client."""

    HELLO = "hello"
    ALERT = "alert"
    STATS = "stats"
    #: JSON line accepted by the parser — emitted *before* any SQL write.
    JSON_ARRIVAL = "json_arrival"
    STATUS_ALERT = "status_alert"
    ERROR = "error"
    SHUTDOWN = "shutdown"


class StreamStats(BaseModel):
    """Periodic pipeline telemetry pushed to live clients.

    ``events_per_second`` / ``events_last_window`` are computed purely in
    process memory from JSON arrivals (see :class:`services.eps_meter.EpsMeter`).
    The WebSocket stats path never queries SQL for the EPS figure.
    """

    events_per_second: float = 0.0
    #: How many events were accepted inside ``eps_window_seconds``.
    events_last_window: int = 0
    eps_window_seconds: float = 1.0
    #: Monotonic-ish wall clock for the sample (unix epoch seconds).
    sample_epoch: float = 0.0
    ingested: int = 0
    #: Best-effort stored count (cached); not used for EPS math.
    stored_events: int = 0
    queue_depth: int = 0
    parse_errors: int = 0
    clients: int = 0
    dropped_frames: int = 0
    #: Explicit marker for clients/docs: EPS fields are SQL-free.
    eps_sql_free: bool = True


class StreamEnvelope(BaseModel):
    """One frame on the wire.

    A single envelope type keeps the browser client simple: it switches on
    ``type`` and never has to guess the shape of the payload.
    """

    type: StreamMessageType
    seq: int = 0
    message: str | None = None
    alert: LogRecord | None = None
    stats: StreamStats | None = None
    data: dict[str, Any] | None = None
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
