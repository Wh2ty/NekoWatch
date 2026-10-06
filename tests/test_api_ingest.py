"""Tests for real-time HTTP push ingest and API source config loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.api_sources_config import load_api_sources_config
from tests.conftest import make_alert


def test_load_api_sources_config(tmp_path: Path) -> None:
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        """
api_active:
  - wazuh_manager
api_sources:
  wazuh_manager:
    type: wazuh
    url: https://wazuh.local:55000
    username: wazuh-wui
    password: secret
    verify_ssl: false
    poll_interval: 7
  idle:
    type: generic
    url: https://example.com/alerts
""",
        encoding="utf-8",
    )
    sources = load_api_sources_config(cfg)
    assert len(sources) == 1
    assert sources[0].name == "wazuh_manager"
    assert sources[0].type == "wazuh"
    assert sources[0].url == "https://wazuh.local:55000"
    assert sources[0].password == "secret"
    assert sources[0].poll_interval == 7.0
    assert sources[0].items_path == "data.affected_items"


def test_push_alerts_json_array(client: TestClient) -> None:
    alerts = [make_alert(offset_seconds=1), make_alert(offset_seconds=2)]
    response = client.post("/api/v1/ingest/alerts", json=alerts)
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 2
    assert body["skipped"] == 0
    assert body["source"] == "api:push"

    # Writer flushes on a timer; wait briefly then search.
    import time

    deadline = time.time() + 3.0
    total = 0
    while time.time() < deadline:
        page = client.get("/api/v1/logs", params={"limit": 10}).json()
        total = page["total"]
        if total >= 2:
            break
        time.sleep(0.1)
    assert total >= 2


def test_push_alerts_ndjson(client: TestClient) -> None:
    lines = "\n".join(
        json.dumps(make_alert(offset_seconds=i)) for i in range(3)
    )
    response = client.post(
        "/api/v1/ingest/alerts",
        content=lines + "\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert response.status_code == 202
    assert response.json()["accepted"] == 3


def test_push_text_endpoint(client: TestClient) -> None:
    payload = json.dumps([make_alert(offset_seconds=5)])
    response = client.post(
        "/api/v1/ingest/text",
        json={"text": payload, "source": "ui"},
    )
    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert response.json()["source"] == "api:ui"


def test_ingest_status_endpoint(client: TestClient) -> None:
    status = client.get("/api/v1/ingest/status")
    assert status.status_code == 200
    data = status.json()
    assert "push_enabled" in data
    assert "sources" in data
    assert isinstance(data["sources"], list)


def test_connect_live_rejects_bad_url(client: TestClient) -> None:
    bad = client.post(
        "/api/v1/ingest/connect",
        json={"url": "ftp://nope", "type": "generic"},
    )
    assert bad.status_code == 400


def test_connect_and_disconnect_live(client: TestClient) -> None:
    """Connect spawns a live poller; disconnect removes it."""
    # Short timeout: first poll against closed port fails fast, source stays up.
    client.app.state.container.settings.api_ingest_timeout = 1.0
    connected = client.post(
        "/api/v1/ingest/connect",
        json={
            "url": "http://127.0.0.1:9/alerts",
            "type": "generic",
            "poll_interval": 60,
            "name": "live",
        },
    )
    assert connected.status_code == 200
    body = connected.json()
    assert body["name"] == "live"
    assert body["url"].startswith("http://127.0.0.1:9")
    assert body["running"] is True

    status = client.get("/api/v1/ingest/status").json()
    assert any(s["name"] == "live" for s in status["sources"])

    gone = client.post("/api/v1/ingest/disconnect?name=live")
    assert gone.status_code == 200
    assert gone.json()["status"] == "disconnected"

    status2 = client.get("/api/v1/ingest/status").json()
    assert not any(s["name"] == "live" for s in status2["sources"])


def test_api_source_env_password_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        """
api_active: [http_json]
api_sources:
  http_json:
    type: generic
    url: https://example.com/alerts
    password: from-yaml
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("NEKOWATCH_API_SOURCE_HTTP_JSON_PASSWORD", "from-env")
    sources = load_api_sources_config(cfg)
    assert sources[0].password == "from-env"


def test_push_requires_token_when_configured(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("NEKOWATCH_INGEST_PUSH_TOKEN", "secret-token")
    from core.config import get_settings

    get_settings.cache_clear()
    # Settings are bound at container create — update live settings object.
    container = client.app.state.container
    container.settings.ingest_push_token = "secret-token"

    denied = client.post("/api/v1/ingest/alerts", json=[make_alert()])
    assert denied.status_code == 401

    ok = client.post(
        "/api/v1/ingest/alerts",
        json=[make_alert(offset_seconds=9)],
        headers={"X-NekoWatch-Token": "secret-token"},
    )
    assert ok.status_code == 202
    assert ok.json()["accepted"] == 1
    get_settings.cache_clear()
