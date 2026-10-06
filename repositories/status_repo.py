"""Persistence for monitored sources, LAN users and status notifications."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from db.models import MonitoredSource, NetworkUser, StatusNotification
from db.session import Database
from domain.status import EventHealth, NetworkReachability, RegistrationStatus


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class StatusRepository:
    """CRUD + heartbeat helpers for the status-monitoring tables."""

    def __init__(self, database: Database) -> None:
        self._db = database

    # --------------------------------------------------------------- sources
    async def list_sources(self) -> list[MonitoredSource]:
        async with self._db.session() as session:
            rows = await session.scalars(
                select(MonitoredSource).order_by(MonitoredSource.name, MonitoredSource.id)
            )
            return list(rows.all())

    async def get_source(self, source_id: int) -> MonitoredSource | None:
        async with self._db.session() as session:
            return await session.get(MonitoredSource, source_id)

    async def get_source_by_agent(self, agent_id: str) -> MonitoredSource | None:
        async with self._db.session() as session:
            return await session.scalar(
                select(MonitoredSource).where(MonitoredSource.agent_id == agent_id)
            )

    async def upsert_source(
        self,
        *,
        agent_id: str,
        name: str | None,
        ip_address: str | None,
        registration: RegistrationStatus = RegistrationStatus.OWN,
        timeout_seconds: int = 60,
    ) -> MonitoredSource:
        now = _utcnow()
        async with self._db.session() as session:
            source = await session.scalar(
                select(MonitoredSource).where(MonitoredSource.agent_id == agent_id)
            )
            if source is None:
                source = MonitoredSource(
                    agent_id=agent_id,
                    name=name,
                    ip_address=ip_address,
                    registration=registration.value,
                    event_status=EventHealth.HEALTHY.value,
                    network_status=NetworkReachability.DISCONNECTED.value,
                    timeout_seconds=timeout_seconds,
                    created_at=now,
                    updated_at=now,
                )
                session.add(source)
            else:
                if name:
                    source.name = name
                if ip_address:
                    source.ip_address = ip_address
                source.registration = registration.value
                source.timeout_seconds = timeout_seconds
                source.updated_at = now
            await session.commit()
            await session.refresh(source)
            return source

    async def touch_source_event(
        self,
        *,
        agent_id: str,
        name: str | None,
        ip_address: str | None,
        seen_at: datetime,
        last_event_seq: int | None,
        event_delta: int,
        default_timeout: int,
        default_registration: RegistrationStatus,
    ) -> tuple[MonitoredSource, bool]:
        """Create/refresh a source on ingest; mark event health as healthy.

        Returns ``(source, created)`` where ``created`` is True on first sight.
        """
        iso = seen_at.astimezone(timezone.utc).isoformat()
        async with self._db.session() as session:
            source = await session.scalar(
                select(MonitoredSource).where(MonitoredSource.agent_id == agent_id)
            )
            created = source is None
            if created:
                source = MonitoredSource(
                    agent_id=agent_id,
                    name=name,
                    ip_address=ip_address,
                    registration=default_registration.value,
                    event_status=EventHealth.HEALTHY.value,
                    network_status=NetworkReachability.DISCONNECTED.value,
                    last_event_at=iso,
                    last_event_seq=last_event_seq,
                    event_count=event_delta,
                    timeout_seconds=default_timeout,
                    created_at=iso,
                    updated_at=iso,
                )
                session.add(source)
            else:
                source.name = name or source.name
                source.ip_address = ip_address or source.ip_address
                source.last_event_at = iso
                if last_event_seq is not None:
                    source.last_event_seq = last_event_seq
                source.event_count = int(source.event_count) + event_delta
                source.event_status = EventHealth.HEALTHY.value
                source.updated_at = iso
            await session.commit()
            await session.refresh(source)
            return source, created

    async def set_source_event_status(
        self, source_id: int, status: EventHealth
    ) -> MonitoredSource | None:
        async with self._db.session() as session:
            source = await session.get(MonitoredSource, source_id)
            if source is None:
                return None
            source.event_status = status.value
            source.updated_at = _utcnow()
            await session.commit()
            await session.refresh(source)
            return source

    async def set_source_network_status(
        self,
        source_id: int,
        status: NetworkReachability,
        *,
        pinged_at: datetime | None = None,
    ) -> MonitoredSource | None:
        async with self._db.session() as session:
            source = await session.get(MonitoredSource, source_id)
            if source is None:
                return None
            source.network_status = status.value
            source.last_ping_at = (pinged_at or datetime.now(timezone.utc)).isoformat()
            source.updated_at = _utcnow()
            await session.commit()
            await session.refresh(source)
            return source

    async def set_registration(
        self, source_id: int, registration: RegistrationStatus
    ) -> MonitoredSource | None:
        """Mark a source as own / foreign."""
        async with self._db.session() as session:
            source = await session.get(MonitoredSource, source_id)
            if source is None:
                return None
            source.registration = registration.value
            source.updated_at = _utcnow()
            await session.commit()
            await session.refresh(source)
            return source

    # ------------------------------------------------------------------ users
    async def list_users(self) -> list[NetworkUser]:
        async with self._db.session() as session:
            rows = await session.scalars(
                select(NetworkUser).order_by(NetworkUser.username)
            )
            return list(rows.all())

    async def upsert_user(
        self,
        *,
        username: str,
        display_name: str | None,
        ip_address: str,
        registration: RegistrationStatus = RegistrationStatus.OWN,
    ) -> NetworkUser:
        now = _utcnow()
        async with self._db.session() as session:
            user = await session.scalar(
                select(NetworkUser).where(NetworkUser.username == username)
            )
            if user is None:
                user = NetworkUser(
                    username=username,
                    display_name=display_name,
                    ip_address=ip_address,
                    registration=registration.value,
                    network_status=NetworkReachability.DISCONNECTED.value,
                    created_at=now,
                    updated_at=now,
                )
                session.add(user)
            else:
                user.display_name = display_name or user.display_name
                user.ip_address = ip_address
                user.registration = registration.value
                user.updated_at = now
            await session.commit()
            await session.refresh(user)
            return user

    async def set_user_network_status(
        self,
        user_id: int,
        status: NetworkReachability,
        *,
        rtt_ms: float | None = None,
        pinged_at: datetime | None = None,
    ) -> NetworkUser | None:
        async with self._db.session() as session:
            user = await session.get(NetworkUser, user_id)
            if user is None:
                return None
            user.network_status = status.value
            user.last_rtt_ms = rtt_ms
            user.last_ping_at = (pinged_at or datetime.now(timezone.utc)).isoformat()
            user.updated_at = _utcnow()
            await session.commit()
            await session.refresh(user)
            return user

    # ----------------------------------------------------------- notifications
    async def create_notification(
        self,
        *,
        kind: str,
        severity: str,
        title: str,
        message: str,
        source_id: int | None,
    ) -> StatusNotification:
        async with self._db.session() as session:
            row = StatusNotification(
                kind=kind,
                severity=severity,
                title=title,
                message=message,
                source_id=source_id,
                acknowledged=False,
                created_at=_utcnow(),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def list_notifications(
        self, *, limit: int = 20, unacknowledged_only: bool = False
    ) -> list[StatusNotification]:
        async with self._db.session() as session:
            stmt = (
                select(StatusNotification)
                .order_by(StatusNotification.id.desc())
                .limit(limit)
            )
            if unacknowledged_only:
                stmt = stmt.where(StatusNotification.acknowledged.is_(False))
            return list((await session.scalars(stmt)).all())

    async def acknowledge(self, notification_id: int) -> StatusNotification | None:
        async with self._db.session() as session:
            row = await session.get(StatusNotification, notification_id)
            if row is None:
                return None
            row.acknowledged = True
            await session.commit()
            await session.refresh(row)
            return row

    async def count_sources(self) -> int:
        async with self._db.session() as session:
            from sqlalchemy import func

            return int(
                await session.scalar(select(func.count()).select_from(MonitoredSource))
                or 0
            )
