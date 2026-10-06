"""Fan-out hub for the live WebSocket feed.

Each client gets a bounded queue and its own server-side filter, so a slow
browser tab can never stall ingestion: when a client's queue is full its
oldest frame is dropped and a counter is incremented, while the pipeline keeps
running at full speed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Sequence

from core.config import Settings
from domain.models import LogRecord
from domain.queries import LogFilter
from domain.stream import StreamEnvelope, StreamMessageType, StreamStats
from services.matching import record_matches

logger = logging.getLogger("nekowatch.live")


@dataclass
class LiveSubscription:
    """One connected live client."""

    client_id: str
    queue: asyncio.Queue[StreamEnvelope]
    log_filter: LogFilter = field(default_factory=LogFilter)
    connected_at: float = field(default_factory=time.time)
    sent: int = 0
    dropped: int = 0


class LiveHub:
    """Registry of live subscribers plus filtered fan-out."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._clients: dict[str, LiveSubscription] = {}
        self._lock = asyncio.Lock()
        self._dropped_frames = 0

    @property
    def client_count(self) -> int:
        """Number of connected clients."""
        return len(self._clients)

    @property
    def dropped_frames(self) -> int:
        """Frames discarded because a client could not keep up."""
        return self._dropped_frames

    async def subscribe(
        self, client_id: str, log_filter: LogFilter | None = None
    ) -> LiveSubscription:
        """Register a client.

        Raises:
            RuntimeError: When ``live_max_clients`` is already reached, so the
                router can reject the socket instead of degrading everyone.
        """
        async with self._lock:
            if len(self._clients) >= self._settings.live_max_clients:
                raise RuntimeError("live_max_clients_exceeded")
            subscription = LiveSubscription(
                client_id=client_id,
                queue=asyncio.Queue(maxsize=self._settings.live_client_queue_size),
                log_filter=log_filter or LogFilter(),
            )
            self._clients[client_id] = subscription
            logger.info("live_client_connected", extra={"client_id": client_id})
            return subscription

    async def unsubscribe(self, client_id: str) -> None:
        """Remove a client, if still registered."""
        async with self._lock:
            subscription = self._clients.pop(client_id, None)
        if subscription is not None:
            logger.info(
                "live_client_disconnected",
                extra={
                    "client_id": client_id,
                    "sent": subscription.sent,
                    "dropped": subscription.dropped,
                },
            )

    async def update_filter(self, client_id: str, log_filter: LogFilter) -> bool:
        """Replace a client's server-side filter mid-connection."""
        async with self._lock:
            subscription = self._clients.get(client_id)
            if subscription is None:
                return False
            subscription.log_filter = log_filter
            return True

    async def publish_records(self, records: Sequence[LogRecord]) -> None:
        """Fan out newly stored alerts to every interested client."""
        if not records or not self._clients:
            return
        async with self._lock:
            subscriptions = list(self._clients.values())
        for record in records:
            for subscription in subscriptions:
                if not record_matches(record, subscription.log_filter):
                    continue
                self._offer(
                    subscription,
                    StreamEnvelope(
                        type=StreamMessageType.ALERT,
                        seq=record.seq,
                        alert=record,
                    ),
                )

    async def broadcast(self, envelope: StreamEnvelope) -> None:
        """Send a non-alert frame (stats, shutdown, error) to every client."""
        async with self._lock:
            subscriptions = list(self._clients.values())
        for subscription in subscriptions:
            self._offer(subscription, envelope)

    async def broadcast_stats(self, stats: StreamStats) -> None:
        """Convenience wrapper for telemetry frames."""
        stats.clients = self.client_count
        stats.dropped_frames = self._dropped_frames
        await self.broadcast(
            StreamEnvelope(type=StreamMessageType.STATS, stats=stats)
        )

    async def broadcast_json_arrival(
        self,
        *,
        count: int,
        events_last_window: int,
        events_per_second: float,
        sample_epoch: float | None = None,
    ) -> None:
        """Push a SQL-free JSON-arrival tick for the live EPS chart."""
        if count <= 0:
            return
        await self.broadcast(
            StreamEnvelope(
                type=StreamMessageType.JSON_ARRIVAL,
                message="json",
                data={
                    "n": int(count),
                    "epoch": float(sample_epoch if sample_epoch is not None else time.time()),
                    "events_last_window": int(events_last_window),
                    "events_per_second": float(events_per_second),
                    "eps_sql_free": True,
                },
            )
        )

    async def shutdown(self) -> None:
        """Tell clients the server is going away and clear the registry."""
        await self.broadcast(
            StreamEnvelope(
                type=StreamMessageType.SHUTDOWN, message="server_shutting_down"
            )
        )
        async with self._lock:
            self._clients.clear()

    def _offer(self, subscription: LiveSubscription, envelope: StreamEnvelope) -> None:
        """Enqueue a frame, dropping the oldest one when the client lags."""
        try:
            subscription.queue.put_nowait(envelope)
            subscription.sent += 1
            return
        except asyncio.QueueFull:
            pass

        try:
            subscription.queue.get_nowait()
        except asyncio.QueueEmpty:  # pragma: no cover - race with the consumer
            pass
        subscription.dropped += 1
        self._dropped_frames += 1
        try:
            subscription.queue.put_nowait(envelope)
            subscription.sent += 1
        except asyncio.QueueFull:  # pragma: no cover - consumer is gone
            pass
