"""Status monitoring: timeout alerting, mock ping, board payload."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from core.config import Settings
from domain.models import LogRecord, Severity
from domain.status import EventHealth, NetworkReachability, RegistrationStatus
from repositories.status_repo import StatusRepository
from services.ping import mock_ping, ping_host
from services.status_monitor import StatusMonitorService


def test_mock_ping_is_deterministic() -> None:
    a = mock_ping("10.0.0.5")
    b = mock_ping("10.0.0.5")
    assert a.ok is b.ok
    assert mock_ping("127.0.0.1").ok is True


@pytest.mark.asyncio
async def test_ping_host_mock_mode() -> None:
    result = await ping_host("192.168.1.10", mock=True)
    assert result.ok is True
    assert result.detail == "mock"


@pytest.mark.asyncio
async def test_foreign_device_alerts_on_first_sight(repo, settings: Settings) -> None:
    cfg = Settings(
        log_file=settings.log_file,
        database_path=settings.database_path,
        sources_config=settings.sources_config,
        source_event_timeout_seconds=60,
        status_monitor_enabled=False,
        generator_autostart=False,
        foreign_device_alert_cooldown=300,
        source_recovery_notify=False,
    )
    service = StatusMonitorService(cfg, StatusRepository(repo.database))
    now = datetime.now(timezone.utc)
    record = LogRecord(
        seq=42,
        timestamp=now,
        severity=Severity.MEDIUM,
        agent_id="rogue-77",
        agent_name="unknown-laptop",
        agent_ip="172.16.9.77",
        message="noise",
    )
    await service.touch_from_records([record])
    board = await service.board()
    source = next(s for s in board.sources if s.agent_id == "rogue-77")
    assert source.registration is RegistrationStatus.FOREIGN
    assert any(n.kind == "foreign_device" for n in board.notifications)

    # Second batch must not spam (cooldown).
    await service.touch_from_records(
        [record.model_copy(update={"seq": 43, "timestamp": now + timedelta(seconds=1)})]
    )
    board2 = await service.board()
    foreign = [n for n in board2.notifications if n.kind == "foreign_device"]
    assert len(foreign) == 1


@pytest.mark.asyncio
async def test_source_timeout_notifies_analysts(repo, settings: Settings) -> None:
    cfg = Settings(
        log_file=settings.log_file,
        database_path=settings.database_path,
        sources_config=settings.sources_config,
        source_event_timeout_seconds=60,
        source_timeout_check_interval=3600,
        status_ping_interval=3600,
        status_ping_mock=True,
        status_monitor_enabled=False,
        generator_autostart=False,
        source_recovery_notify=False,
        foreign_device_alert_cooldown=0,
    )
    service = StatusMonitorService(cfg, StatusRepository(repo.database))

    now = datetime.now(timezone.utc)
    record = LogRecord(
        seq=1,
        timestamp=now - timedelta(seconds=5),
        severity=Severity.LOW,
        agent_id="001",
        agent_name="bank-core-01",
        agent_ip="10.0.0.5",
        message="ok",
    )
    await service.touch_from_records([record])

    board = await service.board()
    source = next(s for s in board.sources if s.agent_id == "001")
    assert source.event_status is EventHealth.HEALTHY
    assert source.is_demo is False

    from db.models import MonitoredSource
    from sqlalchemy import select

    async with repo.database.session() as session:
        row = await session.scalar(
            select(MonitoredSource).where(MonitoredSource.agent_id == "001")
        )
        assert row is not None
        row.last_event_at = (now - timedelta(seconds=90)).isoformat()
        row.timeout_seconds = 60
        await session.commit()

    # Align in-memory clock with the aged DB row.
    async with service._lock:
        host = service._runtime.get("001")
        if host is not None:
            host.last_event_mono = time.monotonic() - 90
            host.last_event_at = now - timedelta(seconds=90)
            host.event_status = EventHealth.HEALTHY

    flipped = await service.evaluate_timeouts()
    assert flipped >= 1
    board = await service.board()
    source = next(s for s in board.sources if s.agent_id == "001")
    assert source.event_status is EventHealth.PROBLEMATIC
    assert any(n.kind == "source_timeout" for n in board.notifications)


@pytest.mark.asyncio
async def test_ping_updates_user_network_status(repo, settings: Settings) -> None:
    cfg = Settings(
        log_file=settings.log_file,
        database_path=settings.database_path,
        status_ping_mock=True,
        status_monitor_enabled=False,
        generator_autostart=False,
    )
    service = StatusMonitorService(cfg, StatusRepository(repo.database))
    await service.register_user(
        username="loopback",
        display_name="Local",
        ip_address="127.0.0.1",
        registration=RegistrationStatus.OWN,
    )
    await service.ping_all()
    board = await service.board()
    user = next(u for u in board.users if u.username == "loopback")
    assert user.network_status is NetworkReachability.CONNECTED
    assert user.connection_label == "Подключён"
    assert user.connection_ok is True


@pytest.mark.asyncio
async def test_live_board_empty_without_devices(repo, settings: Settings) -> None:
    cfg = Settings(
        log_file=settings.log_file,
        database_path=settings.database_path,
        status_monitor_enabled=False,
        generator_autostart=False,
    )
    service = StatusMonitorService(cfg, StatusRepository(repo.database))
    board = await service.board(demo=False)
    assert board.demo is False
    assert board.sources == []
    assert board.users == []
    assert board.notifications == []


def test_demo_board_has_presentation_inventory(settings: Settings) -> None:
    cfg = Settings(
        log_file=settings.log_file,
        database_path=settings.database_path,
        status_monitor_enabled=False,
        generator_autostart=False,
    )
    # demo_board() is pure — repository is unused.
    service = StatusMonitorService(cfg, repo=None)  # type: ignore[arg-type]
    board = service.demo_board()
    assert board.demo is True
    assert len(board.sources) >= 4
    assert any(s.name and s.name.startswith("[DEMO]") for s in board.sources)
    assert all(s.is_demo for s in board.sources)
    assert all(u.is_demo for u in board.users)
    assert any(s.registration is RegistrationStatus.FOREIGN for s in board.sources)
    assert any(s.event_status is EventHealth.PROBLEMATIC for s in board.sources)
    assert any(n.kind == "source_timeout" for n in board.notifications)
