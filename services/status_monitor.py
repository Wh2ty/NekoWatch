"""Production-oriented host monitor: timeouts, rogue devices, LAN ping.

Architecture
------------
* **In-memory runtime map** (``_RuntimeHost``) is the source of truth for
  "last seen" / health flips on the hot ingest path. An ``asyncio.Lock``
  serialises concurrent ``touch_from_records`` vs timeout sweeps.
* **SQLite** persists inventory and notifications for restarts / the board UI.
* **LiveHub** (optional) pushes ``status_alert`` frames so the dashboard reacts
  without polling when a timeout or rogue device fires.

Alerts
------
1. ``source_timeout`` — registered (or any tracked) source silent beyond timeout.
2. ``foreign_device`` — first sight of an unregistered agent on the wire.
3. ``source_recovery`` — optional notice when a timed-out source resumes.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from core.config import Settings
from db.models import MonitoredSource, NetworkUser, StatusNotification
from domain.models import LogRecord
from domain.status import (
    EventHealth,
    NetworkReachability,
    RegistrationStatus,
    SourceStatusCard,
    StatusBoardResponse,
    StatusNotificationOut,
    UserStatusCard,
)
from domain.stream import StreamEnvelope, StreamMessageType
from repositories.status_repo import StatusRepository
from services.ping import ping_host

if TYPE_CHECKING:
    from services.live import LiveHub

logger = logging.getLogger("nekowatch.status")

_REG_LABEL = {
    RegistrationStatus.OWN: 'Зарегистрирован как "свой"',
    RegistrationStatus.FOREIGN: "Не зарегистрирован (чужой)",
}
_CONN_LABEL = {
    NetworkReachability.CONNECTED: "Подключён",
    NetworkReachability.DISCONNECTED: "Нет подключения",
}


@dataclass
class _RuntimeHost:
    """Fast in-process view of one monitored agent (race-safe under lock)."""

    agent_id: str
    source_id: int | None = None
    name: str | None = None
    ip_address: str | None = None
    registration: RegistrationStatus = RegistrationStatus.FOREIGN
    event_status: EventHealth = EventHealth.HEALTHY
    network_status: NetworkReachability = NetworkReachability.DISCONNECTED
    timeout_seconds: int = 60
    last_event_at: datetime | None = None
    last_event_mono: float = 0.0
    last_timeout_alert_mono: float = 0.0
    last_rogue_alert_mono: float = 0.0
    event_count: int = 0


@dataclass(frozen=True, slots=True)
class _TimeoutCandidate:
    agent_id: str
    source_id: int
    timeout_s: int
    name: str | None
    ip: str | None
    age: float
    current: EventHealth


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _source_card(source: MonitoredSource, *, now: datetime) -> SourceStatusCard:
    last_event = _parse_iso(source.last_event_at)
    age: float | None = None
    if last_event is not None:
        age = max(0.0, (now - last_event.astimezone(timezone.utc)).total_seconds())
    registration = RegistrationStatus(source.registration)
    network = NetworkReachability(source.network_status)
    event = EventHealth(source.event_status)
    connection_ok = (
        network is NetworkReachability.CONNECTED and event is EventHealth.HEALTHY
    )
    return SourceStatusCard(
        id=source.id,
        agent_id=source.agent_id,
        name=source.name,
        ip_address=source.ip_address,
        registration=registration,
        registration_label=_REG_LABEL[registration],
        event_status=event,
        network_status=network,
        connection_ok=connection_ok,
        connection_label=(
            _CONN_LABEL[NetworkReachability.CONNECTED]
            if connection_ok
            else _CONN_LABEL[NetworkReachability.DISCONNECTED]
        ),
        last_event_at=last_event,
        last_ping_at=_parse_iso(source.last_ping_at),
        seconds_since_event=age,
        timeout_seconds=source.timeout_seconds,
        event_count=source.event_count,
    )


def _user_card(user: NetworkUser) -> UserStatusCard:
    registration = RegistrationStatus(user.registration)
    network = NetworkReachability(user.network_status)
    connection_ok = network is NetworkReachability.CONNECTED
    return UserStatusCard(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        ip_address=user.ip_address,
        registration=registration,
        registration_label=_REG_LABEL[registration],
        network_status=network,
        connection_ok=connection_ok,
        connection_label=_CONN_LABEL[network],
        last_ping_at=_parse_iso(user.last_ping_at),
        last_rtt_ms=user.last_rtt_ms,
    )


def _notif_out(row: StatusNotification) -> StatusNotificationOut:
    return StatusNotificationOut(
        id=row.id,
        kind=row.kind,
        severity=row.severity,
        title=row.title,
        message=row.message,
        source_id=row.source_id,
        acknowledged=row.acknowledged,
        created_at=_parse_iso(row.created_at) or datetime.now(timezone.utc),
    )


class StatusMonitorService:
    """Owns the timeout sweeper, rogue-device detector and the ping loop."""

    def __init__(
        self,
        settings: Settings,
        repo: StatusRepository,
        hub: LiveHub | None = None,
    ) -> None:
        self._settings = settings
        self._repo = repo
        self._hub = hub
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()
        self._lock = asyncio.Lock()
        self._runtime: dict[str, _RuntimeHost] = {}

    async def start(self) -> None:
        """Hydrate runtime cache from DB, then launch background loops."""
        self._stopping.clear()
        await self._hydrate_runtime()
        if self._settings.status_monitor_enabled:
            self._tasks = [
                asyncio.create_task(self._timeout_loop(), name="nekowatch-src-timeout"),
                asyncio.create_task(self._ping_loop(), name="nekowatch-lan-ping"),
            ]
            logger.info(
                "status_monitor_started",
                extra={
                    "timeout": self._settings.source_event_timeout_seconds,
                    "ping_interval": self._settings.status_ping_interval,
                    "mock_ping": self._settings.status_ping_mock,
                    "hosts_cached": len(self._runtime),
                },
            )

    async def stop(self) -> None:
        """Stop background loops cooperatively."""
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        logger.info("status_monitor_stopped")

    async def _hydrate_runtime(self) -> None:
        """Load existing inventory into the in-memory map (restart safety)."""
        try:
            sources = await self._repo.list_sources()
        except Exception:  # noqa: BLE001
            logger.exception("status_hydrate_failed")
            return
        now_mono = time.monotonic()
        async with self._lock:
            for source in sources:
                last = _parse_iso(source.last_event_at)
                age = 0.0
                if last is not None:
                    age = max(
                        0.0,
                        (datetime.now(timezone.utc) - last.astimezone(timezone.utc)).total_seconds(),
                    )
                self._runtime[source.agent_id] = _RuntimeHost(
                    agent_id=source.agent_id,
                    source_id=source.id,
                    name=source.name,
                    ip_address=source.ip_address,
                    registration=RegistrationStatus(source.registration),
                    event_status=EventHealth(source.event_status),
                    network_status=NetworkReachability(source.network_status),
                    timeout_seconds=int(source.timeout_seconds or 60),
                    last_event_at=last,
                    last_event_mono=now_mono - age,
                    event_count=int(source.event_count or 0),
                )

    async def touch_from_records(self, records: list[LogRecord]) -> None:
        """Update last-seen for every agent in an ingest batch.

        Unknown agents are auto-created as *foreign* and immediately raise a
        ``foreign_device`` alert (with cooldown). Recoveries from timeout emit
        ``source_recovery`` when enabled.
        """
        if not records:
            return
        buckets: dict[str, list[LogRecord]] = defaultdict(list)
        for record in records:
            agent_id = (record.agent_id or record.agent_name or "").strip()
            if not agent_id:
                continue
            buckets[agent_id].append(record)

        timeout = self._settings.source_event_timeout_seconds
        for agent_id, group in buckets.items():
            newest = max(group, key=lambda r: r.epoch)
            await self._heartbeat_agent(
                agent_id=agent_id,
                name=newest.agent_name,
                ip_address=newest.agent_ip,
                seen_at=newest.timestamp,
                last_event_seq=newest.seq,
                event_delta=len(group),
                default_timeout=timeout,
            )

    async def _heartbeat_agent(
        self,
        *,
        agent_id: str,
        name: str | None,
        ip_address: str | None,
        seen_at: datetime,
        last_event_seq: int | None,
        event_delta: int,
        default_timeout: int,
        default_registration: RegistrationStatus = RegistrationStatus.FOREIGN,
    ) -> None:
        was_problematic = False
        created = False
        registration = default_registration
        source_id: int | None = None

        async with self._lock:
            host = self._runtime.get(agent_id)
            if host is not None:
                was_problematic = host.event_status is EventHealth.PROBLEMATIC
                registration = host.registration

        try:
            source, created = await self._repo.touch_source_event(
                agent_id=agent_id,
                name=name,
                ip_address=ip_address,
                seen_at=seen_at,
                last_event_seq=last_event_seq,
                event_delta=event_delta,
                default_timeout=default_timeout,
                default_registration=default_registration,
            )
            source_id = source.id
            registration = RegistrationStatus(source.registration)
        except Exception:  # noqa: BLE001
            logger.exception("status_touch_persist_failed", extra={"agent_id": agent_id})
            # Still update memory so timeout logic keeps working under DB blips.
            source = None

        now_mono = time.monotonic()
        async with self._lock:
            host = self._runtime.get(agent_id)
            if host is None:
                host = _RuntimeHost(agent_id=agent_id)
                self._runtime[agent_id] = host
            host.source_id = source_id or host.source_id
            host.name = name or host.name
            host.ip_address = ip_address or host.ip_address
            host.registration = registration
            host.timeout_seconds = default_timeout if created else host.timeout_seconds
            if source is not None:
                host.timeout_seconds = int(source.timeout_seconds or host.timeout_seconds)
                host.event_count = int(source.event_count or host.event_count)
            else:
                host.event_count += event_delta
            host.last_event_at = seen_at.astimezone(timezone.utc)
            host.last_event_mono = now_mono
            host.event_status = EventHealth.HEALTHY

        if created and registration is RegistrationStatus.FOREIGN:
            await self._alert_rogue_device(
                agent_id=agent_id,
                name=name,
                ip_address=ip_address,
                source_id=source_id,
            )

        if (
            was_problematic
            and self._settings.source_recovery_notify
            and source_id is not None
        ):
            await self._emit_alert(
                kind="source_recovery",
                severity="info",
                title=f"Источник {name or agent_id} снова активен",
                message=(
                    f"Агент «{agent_id}» возобновил отправку событий "
                    f"(IP: {ip_address or '—'})."
                ),
                source_id=source_id,
            )

    async def _alert_rogue_device(
        self,
        *,
        agent_id: str,
        name: str | None,
        ip_address: str | None,
        source_id: int | None,
    ) -> None:
        cooldown = self._settings.foreign_device_alert_cooldown
        now_mono = time.monotonic()
        async with self._lock:
            host = self._runtime.get(agent_id)
            if host is not None:
                if (
                    cooldown > 0
                    and host.last_rogue_alert_mono
                    and now_mono - host.last_rogue_alert_mono < cooldown
                ):
                    return
                host.last_rogue_alert_mono = now_mono

        title = f"Чужое устройство: {name or agent_id}"
        message = (
            f"Обнаружена активность незарегистрированного агента «{agent_id}» "
            f"(IP: {ip_address or '—'}). Зарегистрируйте устройство как «своё» "
            f"или расследуйте проникновение."
        )
        await self._emit_alert(
            kind="foreign_device",
            severity="critical",
            title=title,
            message=message,
            source_id=source_id,
        )
        logger.warning(
            "foreign_device_alert",
            extra={"agent_id": agent_id, "source_id": source_id, "ip": ip_address},
        )

    async def _emit_alert(
        self,
        *,
        kind: str,
        severity: str,
        title: str,
        message: str,
        source_id: int | None,
    ) -> None:
        notif_id: int | None = None
        try:
            row = await self._repo.create_notification(
                kind=kind,
                severity=severity,
                title=title,
                message=message,
                source_id=source_id,
            )
            notif_id = row.id
        except Exception:  # noqa: BLE001
            logger.exception("status_notification_persist_failed", extra={"kind": kind})

        if self._hub is not None:
            try:
                await self._hub.broadcast(
                    StreamEnvelope(
                        type=StreamMessageType.STATUS_ALERT,
                        message=kind,
                        data={
                            "id": notif_id,
                            "kind": kind,
                            "severity": severity,
                            "title": title,
                            "message": message,
                            "source_id": source_id,
                        },
                    )
                )
            except Exception:  # noqa: BLE001
                logger.exception("status_alert_broadcast_failed", extra={"kind": kind})

    async def board(self, *, demo: bool = False) -> StatusBoardResponse:
        """Payload for status cards. ``demo=True`` returns presentation mocks."""
        if demo:
            return self.demo_board()
        now = datetime.now(timezone.utc)
        sources = [_source_card(s, now=now) for s in await self._repo.list_sources()]
        users = [_user_card(u) for u in await self._repo.list_users()]
        notifications = [
            _notif_out(n) for n in await self._repo.list_notifications(limit=15)
        ]
        return StatusBoardResponse(
            sources=sources,
            users=users,
            notifications=notifications,
            source_timeout_seconds=self._settings.source_event_timeout_seconds,
            generated_at=now,
            mock=self._settings.status_ping_mock,
            demo=False,
        )

    def demo_board(self) -> StatusBoardResponse:
        """Presentation-only inventory — intentionally unlike the live seed."""
        now = datetime.now(timezone.utc)
        timeout = self._settings.source_event_timeout_seconds

        def src(
            sid: int,
            agent_id: str,
            name: str,
            ip: str,
            *,
            registration: RegistrationStatus,
            network: NetworkReachability,
            event: EventHealth,
            age_s: float,
            events: int,
        ) -> SourceStatusCard:
            connection_ok = (
                network is NetworkReachability.CONNECTED
                and event is EventHealth.HEALTHY
            )
            return SourceStatusCard(
                id=sid,
                agent_id=agent_id,
                name=name,
                ip_address=ip,
                registration=registration,
                registration_label=_REG_LABEL[registration],
                event_status=event,
                network_status=network,
                connection_ok=connection_ok,
                connection_label=(
                    _CONN_LABEL[NetworkReachability.CONNECTED]
                    if connection_ok
                    else _CONN_LABEL[NetworkReachability.DISCONNECTED]
                ),
                last_event_at=now - timedelta(seconds=age_s),
                last_ping_at=now,
                seconds_since_event=age_s,
                timeout_seconds=timeout,
                event_count=events,
                is_demo=True,
            )

        sources = [
            src(
                9001, "D-HQ-01", "[DEMO] HQ Core Switch", "10.50.0.1",
                registration=RegistrationStatus.OWN,
                network=NetworkReachability.CONNECTED,
                event=EventHealth.HEALTHY, age_s=4, events=98412,
            ),
            src(
                9002, "D-DC-SQL", "[DEMO] SQL Cluster A", "10.50.10.12",
                registration=RegistrationStatus.OWN,
                network=NetworkReachability.CONNECTED,
                event=EventHealth.PROBLEMATIC, age_s=78, events=22190,
            ),
            src(
                9003, "D-VPN-GW", "[DEMO] VPN Gateway", "10.50.20.5",
                registration=RegistrationStatus.OWN,
                network=NetworkReachability.DISCONNECTED,
                event=EventHealth.PROBLEMATIC, age_s=420, events=5501,
            ),
            src(
                9004, "D-UNK-77", "[DEMO] Неизвестный хост", "172.16.9.77",
                registration=RegistrationStatus.FOREIGN,
                network=NetworkReachability.CONNECTED,
                event=EventHealth.HEALTHY, age_s=9, events=126,
            ),
            src(
                9005, "D-IOT-CAM", "[DEMO] Чужая IP-камера", "172.16.9.201",
                registration=RegistrationStatus.FOREIGN,
                network=NetworkReachability.DISCONNECTED,
                event=EventHealth.PROBLEMATIC, age_s=900, events=2,
            ),
            src(
                9006, "D-DR-BK", "[DEMO] DR Backup Node", "10.60.0.8",
                registration=RegistrationStatus.OWN,
                network=NetworkReachability.DISCONNECTED,
                event=EventHealth.HEALTHY, age_s=15, events=3300,
            ),
        ]
        users = [
            UserStatusCard(
                id=9101, username="demo.soc.lead", display_name="[DEMO] SOC Lead",
                ip_address="10.50.100.2", registration=RegistrationStatus.OWN,
                registration_label=_REG_LABEL[RegistrationStatus.OWN],
                network_status=NetworkReachability.CONNECTED, connection_ok=True,
                connection_label=_CONN_LABEL[NetworkReachability.CONNECTED],
                last_ping_at=now, last_rtt_ms=3.0, is_demo=True,
            ),
            UserStatusCard(
                id=9102, username="demo.analyst.offsite",
                display_name="[DEMO] Analyst (offline)",
                ip_address="10.50.100.44", registration=RegistrationStatus.OWN,
                registration_label=_REG_LABEL[RegistrationStatus.OWN],
                network_status=NetworkReachability.DISCONNECTED, connection_ok=False,
                connection_label=_CONN_LABEL[NetworkReachability.DISCONNECTED],
                last_ping_at=now, last_rtt_ms=None, is_demo=True,
            ),
            UserStatusCard(
                id=9103, username="demo.contractor",
                display_name="[DEMO] Подрядчик (чужой)",
                ip_address="172.16.9.50", registration=RegistrationStatus.FOREIGN,
                registration_label=_REG_LABEL[RegistrationStatus.FOREIGN],
                network_status=NetworkReachability.CONNECTED, connection_ok=True,
                connection_label=_CONN_LABEL[NetworkReachability.CONNECTED],
                last_ping_at=now, last_rtt_ms=41.0, is_demo=True,
            ),
        ]
        notifications = [
            StatusNotificationOut(
                id=9201, kind="source_timeout", severity="high",
                title="[DEMO] SQL Cluster A — нет событий > 60с",
                message=(
                    "Таймаут: агент D-DC-SQL молчит 78 с. "
                    "Карточка переведена в «проблемный»."
                ),
                source_id=9002, acknowledged=False,
                created_at=now - timedelta(seconds=18),
            ),
            StatusNotificationOut(
                id=9202, kind="source_timeout", severity="critical",
                title="[DEMO] VPN Gateway недоступен",
                message="Ping: нет ответа + нет событий 420 с.",
                source_id=9003, acknowledged=False,
                created_at=now - timedelta(seconds=40),
            ),
            StatusNotificationOut(
                id=9203, kind="foreign_device", severity="critical",
                title="[DEMO] Обнаружен незарегистрированный хост",
                message=(
                    "172.16.9.77 шлёт события, но не в инвентаре («чужой»)."
                ),
                source_id=9004, acknowledged=False,
                created_at=now - timedelta(seconds=5),
            ),
        ]
        return StatusBoardResponse(
            sources=sources,
            users=users,
            notifications=notifications,
            source_timeout_seconds=timeout,
            generated_at=now,
            mock=True,
            demo=True,
        )

    async def evaluate_timeouts(self) -> int:
        """Flip stale sources to problematic and notify analysts.

        Uses the in-memory last-seen clock when available (avoids races with
        concurrent ingest heartbeats), falling back to DB timestamps.
        """
        now = datetime.now(timezone.utc)
        now_mono = time.monotonic()
        flipped = 0
        cooldown = self._settings.source_timeout_alert_cooldown

        async with self._lock:
            runtime_items = list(self._runtime.values())

        db_sources = {s.agent_id: s for s in await self._repo.list_sources()}
        seen_agents = {h.agent_id for h in runtime_items}

        candidates: list[_TimeoutCandidate] = []
        for host in runtime_items:
            age = (
                now_mono - host.last_event_mono
                if host.last_event_mono > 0
                else float("inf")
            )
            candidates.append(
                _TimeoutCandidate(
                    host.agent_id,
                    host.source_id or 0,
                    host.timeout_seconds,
                    host.name,
                    host.ip_address,
                    age,
                    host.event_status,
                )
            )

        for agent_id, source in db_sources.items():
            if agent_id in seen_agents:
                continue
            last = _parse_iso(source.last_event_at)
            age = (
                float("inf")
                if last is None
                else (now - last.astimezone(timezone.utc)).total_seconds()
            )
            candidates.append(
                _TimeoutCandidate(
                    agent_id,
                    source.id,
                    int(source.timeout_seconds or 60),
                    source.name,
                    source.ip_address,
                    age,
                    EventHealth(source.event_status),
                )
            )

        for cand in candidates:
            should_be = (
                EventHealth.PROBLEMATIC
                if cand.age >= cand.timeout_s
                else EventHealth.HEALTHY
            )

            if should_be is EventHealth.HEALTHY:
                if cand.current is EventHealth.PROBLEMATIC and cand.source_id:
                    await self._repo.set_source_event_status(
                        cand.source_id, EventHealth.HEALTHY
                    )
                    async with self._lock:
                        host = self._runtime.get(cand.agent_id)
                        if host is not None:
                            host.event_status = EventHealth.HEALTHY
                continue

            # should_be == PROBLEMATIC
            first_flip = cand.current is not EventHealth.PROBLEMATIC
            fire_alert = first_flip
            async with self._lock:
                host = self._runtime.get(cand.agent_id)
                if host is not None:
                    if first_flip:
                        host.event_status = EventHealth.PROBLEMATIC
                    elif cooldown > 0:
                        fire_alert = (
                            now_mono - host.last_timeout_alert_mono
                        ) >= cooldown
                    if fire_alert:
                        host.last_timeout_alert_mono = now_mono

            if first_flip and cand.source_id:
                await self._repo.set_source_event_status(
                    cand.source_id, EventHealth.PROBLEMATIC
                )
                flipped += 1

            if fire_alert:
                age_disp = int(cand.age) if cand.age != float("inf") else cand.timeout_s
                await self._emit_alert(
                    kind="source_timeout",
                    severity="high",
                    title=f"Источник {cand.name or cand.agent_id} проблемный",
                    message=(
                        f"Нет событий от агента «{cand.agent_id}» "
                        f"более {cand.timeout_s} с "
                        f"(тишина ≈ {age_disp} с, IP: {cand.ip or '—'})."
                    ),
                    source_id=cand.source_id or None,
                )
                logger.warning(
                    "source_timeout_alert",
                    extra={
                        "agent_id": cand.agent_id,
                        "source_id": cand.source_id,
                        "age": cand.age,
                    },
                )

        return flipped

    async def ping_all(self) -> None:
        """ICMP-probe every source IP and every LAN user (bounded concurrency)."""
        mock = self._settings.status_ping_mock
        timeout_ms = self._settings.status_ping_timeout_ms
        concurrency = self._settings.status_ping_concurrency
        now = datetime.now(timezone.utc)
        sem = asyncio.Semaphore(concurrency)

        sources = await self._repo.list_sources()
        users = await self._repo.list_users()

        async def _probe_source(source: MonitoredSource) -> None:
            if not source.ip_address:
                return
            async with sem:
                try:
                    result = await ping_host(
                        source.ip_address, timeout_ms=timeout_ms, mock=mock
                    )
                except Exception:  # noqa: BLE001 - never kill the sweep
                    logger.exception(
                        "source_ping_failed", extra={"agent_id": source.agent_id}
                    )
                    result_ok = False
                else:
                    result_ok = result.ok
            status = (
                NetworkReachability.CONNECTED
                if result_ok
                else NetworkReachability.DISCONNECTED
            )
            try:
                await self._repo.set_source_network_status(
                    source.id, status, pinged_at=now
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "source_ping_persist_failed", extra={"source_id": source.id}
                )
            async with self._lock:
                host = self._runtime.get(source.agent_id)
                if host is not None:
                    host.network_status = status

        async def _probe_user(user: NetworkUser) -> None:
            async with sem:
                try:
                    result = await ping_host(
                        user.ip_address, timeout_ms=timeout_ms, mock=mock
                    )
                except Exception:  # noqa: BLE001
                    logger.exception(
                        "user_ping_failed", extra={"username": user.username}
                    )
                    result_ok, rtt = False, None
                else:
                    result_ok, rtt = result.ok, result.rtt_ms
            status = (
                NetworkReachability.CONNECTED
                if result_ok
                else NetworkReachability.DISCONNECTED
            )
            try:
                await self._repo.set_user_network_status(
                    user.id, status, rtt_ms=rtt, pinged_at=now
                )
            except Exception:  # noqa: BLE001
                logger.exception("user_ping_persist_failed", extra={"user_id": user.id})

        await asyncio.gather(
            *(_probe_source(s) for s in sources),
            *(_probe_user(u) for u in users),
            return_exceptions=True,
        )

    async def acknowledge(self, notification_id: int) -> StatusNotificationOut | None:
        row = await self._repo.acknowledge(notification_id)
        return _notif_out(row) if row else None

    async def register_source(
        self,
        *,
        agent_id: str,
        name: str | None,
        ip_address: str | None,
        registration: RegistrationStatus,
        timeout_seconds: int,
    ) -> SourceStatusCard:
        source = await self._repo.upsert_source(
            agent_id=agent_id,
            name=name,
            ip_address=ip_address,
            registration=registration,
            timeout_seconds=timeout_seconds,
        )
        await self._repo.touch_source_event(
            agent_id=agent_id,
            name=name,
            ip_address=ip_address,
            seen_at=datetime.now(timezone.utc),
            last_event_seq=None,
            event_delta=0,
            default_timeout=timeout_seconds,
            default_registration=registration,
        )
        async with self._lock:
            host = self._runtime.get(agent_id) or _RuntimeHost(agent_id=agent_id)
            host.source_id = source.id
            host.name = name or host.name
            host.ip_address = ip_address or host.ip_address
            host.registration = registration
            host.timeout_seconds = timeout_seconds
            host.event_status = EventHealth.HEALTHY
            host.last_event_at = datetime.now(timezone.utc)
            host.last_event_mono = time.monotonic()
            self._runtime[agent_id] = host

        if ip_address:
            result = await ping_host(
                ip_address,
                timeout_ms=self._settings.status_ping_timeout_ms,
                mock=self._settings.status_ping_mock,
            )
            refreshed = await self._repo.get_source_by_agent(agent_id)
            if refreshed is not None:
                await self._repo.set_source_network_status(
                    refreshed.id,
                    (
                        NetworkReachability.CONNECTED
                        if result.ok
                        else NetworkReachability.DISCONNECTED
                    ),
                )
        loaded = await self._repo.get_source_by_agent(agent_id)
        assert loaded is not None
        return _source_card(loaded, now=datetime.now(timezone.utc))

    async def claim_source(self, source_id: int) -> SourceStatusCard | None:
        """Mark an unknown/foreign source as owned inventory."""
        source = await self._repo.set_registration(
            source_id, RegistrationStatus.OWN
        )
        if source is not None:
            async with self._lock:
                host = self._runtime.get(source.agent_id)
                if host is not None:
                    host.registration = RegistrationStatus.OWN
        return (
            _source_card(source, now=datetime.now(timezone.utc)) if source else None
        )

    async def register_user(
        self,
        *,
        username: str,
        display_name: str | None,
        ip_address: str,
        registration: RegistrationStatus,
    ) -> UserStatusCard:
        user = await self._repo.upsert_user(
            username=username,
            display_name=display_name,
            ip_address=ip_address,
            registration=registration,
        )
        return _user_card(user)

    async def _timeout_loop(self) -> None:
        interval = self._settings.source_timeout_check_interval
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            if self._stopping.is_set():
                break
            try:
                await self.evaluate_timeouts()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("source_timeout_loop_error")

    async def _ping_loop(self) -> None:
        interval = self._settings.status_ping_interval
        try:
            await self.ping_all()
        except Exception:  # noqa: BLE001
            logger.exception("status_ping_initial_error")
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            if self._stopping.is_set():
                break
            try:
                await self.ping_all()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("status_ping_loop_error")
