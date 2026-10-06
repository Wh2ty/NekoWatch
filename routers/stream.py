"""Live alert feed over WebSocket.

Protocol
--------
Server frames are :class:`~domain.stream.StreamEnvelope` objects discriminated
by ``type``: ``hello`` on connect (and as an idle keep-alive), ``alert`` per
event, ``stats`` every couple of seconds, ``error`` for bad input, ``shutdown``
on graceful stop.

Clients may send ``{"action": "filter", "filter": {...}}`` to replace their
server-side filter mid-connection, or ``{"action": "ping"}``.

Concurrency note
----------------
Each socket runs a sender and a receiver task that are shut down
*cooperatively* via a shared event — never by cancellation. Cancelling a task
that is blocked on a socket read leaks ``CancelledError`` into the surrounding
ASGI task group, which shows up as spurious errors on shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError

from core.container import ServiceContainer
from domain.queries import LogFilter
from domain.stream import StreamEnvelope, StreamMessageType
from routers.dependencies import get_ws_container
from services.live import LiveSubscription

logger = logging.getLogger("nekowatch.stream")

router = APIRouter(prefix="/api/v1/stream", tags=["stream"])

#: How often the sender wakes to check its queue and the stop flag.
_POLL_INTERVAL = 0.05


@router.websocket("/logs")
async def stream_logs(
    websocket: WebSocket,
    q: str = Query("", max_length=200),
    severity: list[str] = Query([]),
    min_level: int | None = Query(None, ge=0, le=15),
    rule_id: list[str] = Query([]),
    src_ip: list[str] = Query([]),
    mitre_technique: list[str] = Query([]),
) -> None:
    """Stream matching alerts to the browser as they are ingested.

    Filtering happens server-side, so a narrow filter costs the client nothing
    and a busy feed cannot flood a quiet tab.
    """
    container = get_ws_container(websocket)
    if container is None:  # pragma: no cover - startup race
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    try:
        log_filter = LogFilter(
            q=q,
            severities=severity,
            min_level=min_level,
            rule_ids=rule_id,
            src_ips=src_ip,
            mitre_techniques=mitre_technique,
        )
    except ValidationError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()

    client_id = f"ws-{uuid.uuid4().hex[:12]}"
    try:
        subscription = await container.hub.subscribe(client_id, log_filter)
    except RuntimeError:
        # Capacity reached: refuse cleanly instead of degrading every client.
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    await websocket.send_text(
        StreamEnvelope(
            type=StreamMessageType.HELLO,
            message="subscribed",
            data={
                "client_id": client_id,
                "filter": log_filter.describe(),
                "log_file": str(container.settings.log_file),
            },
        ).model_dump_json()
    )

    stop = asyncio.Event()
    sender = asyncio.create_task(
        _pump(websocket, subscription, container.settings.live_heartbeat_interval, stop),
        name=f"{client_id}-sender",
    )
    receiver = asyncio.create_task(
        _listen(websocket, container, client_id, stop), name=f"{client_id}-receiver"
    )

    try:
        await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop.set()
        # Closing the socket unblocks a receiver still waiting on a frame,
        # letting both tasks finish on their own.
        with contextlib.suppress(Exception):
            await websocket.close()
        for result in await asyncio.gather(sender, receiver, return_exceptions=True):
            if isinstance(result, Exception) and not isinstance(
                result, (WebSocketDisconnect, asyncio.CancelledError)
            ):
                logger.warning("stream_task_failed", exc_info=result)
        await container.hub.unsubscribe(client_id)


async def _pump(
    websocket: WebSocket,
    subscription: LiveSubscription,
    heartbeat: float,
    stop: asyncio.Event,
) -> None:
    """Forward queued frames to the socket until asked to stop.

    Polls rather than blocking on the queue so it can observe ``stop`` without
    being cancelled. A disconnect is normal operation and exits quietly.
    """
    last_send = time.monotonic()
    try:
        while not stop.is_set():
            try:
                envelope = subscription.queue.get_nowait()
            except asyncio.QueueEmpty:
                if time.monotonic() - last_send >= heartbeat:
                    await websocket.send_text(
                        StreamEnvelope(
                            type=StreamMessageType.HELLO, message="keepalive"
                        ).model_dump_json()
                    )
                    last_send = time.monotonic()
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            await websocket.send_text(envelope.model_dump_json())
            last_send = time.monotonic()
            if envelope.type is StreamMessageType.SHUTDOWN:
                return
    except (WebSocketDisconnect, RuntimeError):
        return


async def _listen(
    websocket: WebSocket,
    container: ServiceContainer,
    client_id: str,
    stop: asyncio.Event,
) -> None:
    """Handle client control messages until the socket closes."""
    try:
        while not stop.is_set():
            try:
                payload = await websocket.receive_json()
            except (json.JSONDecodeError, UnicodeDecodeError):
                await _send_error(websocket, "invalid_json")
                continue

            if not isinstance(payload, dict):
                await _send_error(websocket, "expected_json_object")
                continue

            action = str(payload.get("action", "")).lower()

            if action == "ping":
                await websocket.send_text(
                    StreamEnvelope(
                        type=StreamMessageType.HELLO, message="pong"
                    ).model_dump_json()
                )
            elif action == "filter":
                await _apply_filter(websocket, container, client_id, payload)
            else:
                await _send_error(websocket, "unknown_action")
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        stop.set()


async def _apply_filter(
    websocket: WebSocket,
    container: ServiceContainer,
    client_id: str,
    payload: dict[str, object],
) -> None:
    """Replace a client's server-side filter."""
    try:
        updated = LogFilter.model_validate(payload.get("filter", {}))
    except ValidationError as exc:
        await _send_error(websocket, "invalid_filter", {"errors": exc.error_count()})
        return

    await container.hub.update_filter(client_id, updated)
    await websocket.send_text(
        StreamEnvelope(
            type=StreamMessageType.HELLO,
            message="filter_updated",
            data={"filter": updated.describe()},
        ).model_dump_json()
    )


async def _send_error(
    websocket: WebSocket, message: str, data: dict[str, object] | None = None
) -> None:
    """Send an error frame to one client."""
    await websocket.send_text(
        StreamEnvelope(
            type=StreamMessageType.ERROR, message=message, data=data
        ).model_dump_json()
    )
