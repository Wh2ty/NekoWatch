"""Shared fixtures: isolated settings, a seeded repository and an API client.

Every test gets its own SQLite file and alert file under ``tmp_path``, so the
suite never touches the developer's real data directory and tests stay
order-independent.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from core.config import Settings, get_settings
from repositories.sqlalchemy_repo import SqlAlchemyLogRepository
from services.parser import AlertParser

BASE_TIME = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def make_alert(
    *,
    rule_id: str = "5712",
    level: int = 10,
    description: str = "Authentication failed",
    offset_seconds: float = 0.0,
    src_ip: str = "185.220.101.44",
    dst_ip: str = "10.0.0.5",
    user: str = "alice",
    service: str = "sshd",
    groups: list[str] | None = None,
    log_level: str = "WARN",
    mail: bool = False,
) -> dict[str, Any]:
    """Build a Wazuh-shaped alert dict in Logener's output format."""
    when = BASE_TIME + timedelta(seconds=offset_seconds)
    payload = {
        "timestamp": when.isoformat(),
        "service": service,
        "level": log_level,
        "user_id": user,
        "ip": src_ip,
        "message": description,
        "device_fingerprint": "fp-1234",
    }
    return {
        "timestamp": when.isoformat(),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "groups": groups or ["authentication_failed", "syslog"],
            "mail": mail,
        },
        "agent": {"id": "001", "name": "bank-core-01", "ip": dst_ip},
        "manager": {"name": "wazuh-manager"},
        "id": f"1690000000.{int(offset_seconds * 1000)}",
        "full_log": json.dumps(payload),
        "decoder": {"name": "json"},
        "location": "/var/log/bank/app.json",
    }


def brute_force_alerts(count: int = 8, step: float = 3.0) -> list[dict[str, Any]]:
    """A burst of authentication failures from one source, ``step`` s apart."""
    return [
        make_alert(offset_seconds=index * step, user=f"user{index % 3}")
        for index in range(count)
    ]


def mixed_alerts() -> list[dict[str, Any]]:
    """A small corpus covering every severity bucket and several rules."""
    return [
        make_alert(
            rule_id="5710",
            level=3,
            description="Successful authentication",
            groups=["authentication_success"],
            offset_seconds=0,
            log_level="INFO",
        ),
        make_alert(
            rule_id="100200",
            level=7,
            description="Large transfer detected",
            groups=["banking", "transaction"],
            offset_seconds=30,
            src_ip="192.168.1.20",
            user="bob",
            service="payments",
            mail=True,
        ),
        make_alert(
            rule_id="5712",
            level=10,
            description="Authentication failed",
            offset_seconds=60,
        ),
        make_alert(
            rule_id="100300",
            level=13,
            description="Impossible travel detected",
            groups=["geo_anomaly", "authentication"],
            offset_seconds=90,
            src_ip="45.13.7.9",
            user="carol",
            service="auth",
            log_level="ERROR",
            mail=True,
        ),
    ]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointing at throw-away paths with background workers off."""
    return Settings(
        log_file=tmp_path / "wazuh_alerts.json",
        # Missing YAML → ingestion falls back to log_file (isolated per test).
        sources_config=tmp_path / "sources.yaml",
        database_path=tmp_path / "nekowatch.sqlite3",
        generator_autostart=False,
        generator_reset_on_start=False,
    )


@pytest.fixture
def parser() -> AlertParser:
    """A fresh parser with zeroed counters."""
    return AlertParser()


@pytest.fixture
async def repo(settings: Settings) -> AsyncIterator[SqlAlchemyLogRepository]:
    """An initialised repository; closed afterwards so the engine exits cleanly."""
    repository = SqlAlchemyLogRepository(settings.database_path)
    await repository.initialize()
    try:
        yield repository
    finally:
        await repository.close()


@pytest.fixture
async def seeded(
    repo: SqlAlchemyLogRepository, parser: AlertParser
) -> SqlAlchemyLogRepository:
    """Repository preloaded with the mixed corpus plus a brute-force burst."""
    batch = []
    for alert in mixed_alerts() + brute_force_alerts():
        raw = json.dumps(alert)
        parsed = parser.parse_line(raw)
        assert parsed is not None
        batch.append(parsed)
    await repo.insert_many(batch)
    return repo


@pytest.fixture
def client(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A TestClient whose app runs the real lifespan against tmp paths."""
    for field, value in {
        "NEKOWATCH_LOG_FILE": settings.log_file,
        "NEKOWATCH_SOURCES_CONFIG": settings.sources_config,
        "NEKOWATCH_DATABASE_PATH": settings.database_path,
        "NEKOWATCH_GENERATOR_AUTOSTART": "false",
        "NEKOWATCH_LIVE_STATS_INTERVAL": "0.2",
        "NEKOWATCH_STATUS_MONITOR_ENABLED": "false",
        "NEKOWATCH_STATUS_PING_MOCK": "true",
    }.items():
        monkeypatch.setenv(field, str(value))
    get_settings.cache_clear()

    from app import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


@pytest.fixture
def seeded_client(client: TestClient) -> TestClient:
    """API client whose store already contains the test corpus."""
    container = client.app.state.container
    parser_ = AlertParser()
    batch = []
    for alert in mixed_alerts() + brute_force_alerts():
        raw = json.dumps(alert)
        parsed = parser_.parse_line(raw)
        assert parsed is not None
        batch.append(parsed)
    client.portal.call(container.repository.insert_many, batch)
    return client
