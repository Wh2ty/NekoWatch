"""End-to-end API tests over the real application (search, charts, export,
correlation, triage, live stream and pages)."""

from __future__ import annotations

import csv
import io
import json

from fastapi.testclient import TestClient


def test_health_and_ingestion_status(client: TestClient) -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] in {"ok", "degraded"}

    status = client.get("/api/v1/ingestion/status")
    assert status.status_code == 200
    assert "log_file" in status.json()


def test_api_connect_page_renders(client: TestClient) -> None:
    page = client.get("/api")
    assert page.status_code == 200
    assert "text/html" in page.headers.get("content-type", "")
    assert 'id="api-url"' in page.text
    assert 'id="btn-api-connect"' in page.text
    assert "Подключение внешнего API" in page.text


def test_search_supports_filters_and_pagination(seeded_client: TestClient) -> None:
    page = seeded_client.get("/api/v1/logs", params={"limit": 5}).json()
    assert page["total"] == 12
    assert page["returned"] == 5

    high = seeded_client.get("/api/v1/logs", params={"severity": "critical"}).json()
    assert high["total"] == 1
    assert high["items"][0]["rule_id"] == "100300"

    text = seeded_client.get("/api/v1/logs", params={"q": "impossible"}).json()
    assert text["total"] == 1

    by_ip = seeded_client.get(
        "/api/v1/logs", params={"src_ip": "185.220.101.44", "min_level": 8}
    ).json()
    assert by_ip["total"] == 9

    by_attack = seeded_client.get(
        "/api/v1/logs", params={"mitre_technique": "T1110"}
    ).json()
    assert by_attack["total"] >= 9


def test_inverted_range_is_rejected(seeded_client: TestClient) -> None:
    response = seeded_client.get(
        "/api/v1/logs", params={"min_level": 10, "max_level": 3}
    )

    assert response.status_code == 422
    assert response.json()["detail"]


def test_alert_detail_and_404(seeded_client: TestClient) -> None:
    detail = seeded_client.get("/api/v1/logs/1").json()
    assert detail["record"]["seq"] == 1
    assert detail["ecs"]["rule"]["id"] == "5710"
    assert detail["payload"]["agent"]["name"] == "bank-core-01"

    assert seeded_client.get("/api/v1/logs/9999").status_code == 404


def test_dashboard_returns_every_chart_dataset(seeded_client: TestClient) -> None:
    data = seeded_client.get(
        "/api/v1/analytics/dashboard", params={"interval": "1m"}
    ).json()

    assert data["overview"]["total_events"] == 12
    assert sum(point["count"] for point in data["timeline"]["points"]) == 12
    assert sum(item["count"] for item in data["severity"]["items"]) == 12
    assert data["top_rules"][0]["rule_id"] == "5712"
    assert data["top_source_ips"][0]["ip"] == "185.220.101.44"
    assert data["top_destination_ips"]
    assert any(t["id"] == "TA0006" for t in data["mitre"]["tactics"])
    assert data["top_users"] and data["top_services"]


def test_analytics_endpoints_respect_the_filter(seeded_client: TestClient) -> None:
    timeline = seeded_client.get(
        "/api/v1/analytics/timeline", params={"interval": "1m", "rule_id": "100300"}
    ).json()
    assert timeline["total"] == 1

    severity = seeded_client.get("/api/v1/analytics/severity").json()
    assert severity["total"] == 12

    top_ips = seeded_client.get(
        "/api/v1/analytics/top-ips", params={"direction": "destination"}
    ).json()
    assert top_ips[0]["count"] >= 1

    assert (
        seeded_client.get("/api/v1/analytics/top-fields/not_a_column").status_code == 400
    )


def test_correlation_groups_and_brute_force(seeded_client: TestClient) -> None:
    groups = seeded_client.get(
        "/api/v1/correlation/groups", params={"min_count": 2}
    ).json()
    assert groups[0]["count"] == 9

    incidents = seeded_client.get(
        "/api/v1/correlation/brute-force",
        params={"window_seconds": 60, "threshold": 5},
    ).json()
    assert len(incidents) == 1
    assert incidents[0]["src_ip"] == "185.220.101.44"
    assert incidents[0]["attempts"] >= 5
    assert incidents[0]["confidence"] in {"low", "medium", "high"}

    quiet = seeded_client.get(
        "/api/v1/correlation/brute-force",
        params={"window_seconds": 1, "threshold": 5},
    ).json()
    assert quiet == []

    combined = seeded_client.get("/api/v1/correlation").json()
    assert combined["groups"] and combined["brute_force"]


def test_triage_workflow(seeded_client: TestClient) -> None:
    bulk = seeded_client.post(
        "/api/v1/triage/bulk",
        json={"seqs": [1, 2], "status": "in_progress", "analyst": "vlad"},
    ).json()
    assert bulk["updated"] == 2

    single = seeded_client.patch(
        "/api/v1/triage/1",
        json={"status": "false_positive", "analyst": "vlad", "note": "test traffic"},
    ).json()
    assert single["records"][0]["triage"]["status"] == "false_positive"

    history = seeded_client.get("/api/v1/triage/1/history").json()
    assert [event["status"] for event in history] == ["in_progress", "false_positive"]

    summary = seeded_client.get("/api/v1/triage/summary").json()
    assert summary["total"] == 12
    by_status = {item["key"]: item["count"] for item in summary["by_status"]}
    assert by_status["in_progress"] == 1
    assert by_status["false_positive"] == 1

    queue = seeded_client.get(
        "/api/v1/triage/queue", params={"triage": "in_progress"}
    ).json()
    assert queue["total"] == 1

    assert (
        seeded_client.patch("/api/v1/triage/9999", json={"status": "resolved"}).status_code
        == 404
    )


def test_csv_export_is_streamed_and_flat(seeded_client: TestClient) -> None:
    response = seeded_client.get("/api/v1/export", params={"format": "csv"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]

    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 12
    assert rows[0]["rule_id"]


def test_json_and_ecs_exports(seeded_client: TestClient) -> None:
    payload = seeded_client.get(
        "/api/v1/export", params={"format": "json", "severity": "critical"}
    ).json()
    assert payload["count"] == 1
    assert len(payload["events"]) == 1
    assert payload["export"]["schema"] == "nekowatch-flat"

    ndjson = seeded_client.get(
        "/api/v1/export", params={"format": "jsonl", "ecs": "true"}
    ).text
    documents = [json.loads(line) for line in ndjson.splitlines() if line.strip()]
    assert len(documents) == 12
    assert documents[0]["event"]["kind"] == "alert"


def test_metadata_endpoints(client: TestClient) -> None:
    mitre = client.get("/api/v1/meta/mitre").json()
    assert any(item["technique_id"] == "T1110" for item in mitre["techniques"])

    fields = client.get("/api/v1/meta/fields").json()
    assert "severity" in json.dumps(fields)


def test_live_stream_pushes_stats_and_alerts(seeded_client: TestClient) -> None:
    container = seeded_client.app.state.container
    records = seeded_client.portal.call(
        container.query.search,
        __import__("domain.queries", fromlist=["LogFilter"]).LogFilter(),
        __import__("domain.queries", fromlist=["Pagination"]).Pagination(limit=1),
    )

    ws_cm = seeded_client.websocket_connect("/api/v1/stream/logs")
    ws = ws_cm.__enter__()
    try:
        hello = ws.receive_json()
        assert hello["type"] == "hello"

        seeded_client.portal.call(container.hub.publish_records, records.items)
        frames = [ws.receive_json() for _ in range(4)]
    finally:
        # Starlette TestClient on Python 3.14 may raise CancelledError while
        # draining the ASGI websocket task group after a clean read.
        try:
            ws_cm.__exit__(None, None, None)
        except BaseException as exc:  # noqa: BLE001
            if type(exc).__name__ != "CancelledError":
                raise

    kinds = {frame["type"] for frame in frames}
    assert "alert" in kinds or "stats" in kinds


def test_pages_render(client: TestClient) -> None:
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "chart-timeline" in dashboard.text
    assert "dashboard.js" in dashboard.text
    assert "status-board" in dashboard.text
    assert "status-source-cards" in dashboard.text
    assert "register-modal" in dashboard.text
    assert "demo-mode" not in dashboard.text
    assert 'data-fold="ai"' in dashboard.text
    assert 'data-fold="charts"' in dashboard.text
    assert 'data-fold="filters"' in dashboard.text
    assert 'data-fold="logs"' in dashboard.text
    assert 'id="chart-eps"' in dashboard.text
    # Panel order: neural → charts → filters → logs
    assert dashboard.text.index('data-fold="ai"') < dashboard.text.index('data-fold="charts"')
    assert dashboard.text.index('data-fold="charts"') < dashboard.text.index('data-fold="filters"')
    assert dashboard.text.index('data-fold="filters"') < dashboard.text.index('data-fold="logs"')

    generator = client.get("/logener")
    assert generator.status_code == 200
    assert "Logener" in generator.text
    assert "demo-mode" in generator.text
    assert "btn-full-reset" in generator.text
    assert "btn-start-reset" not in generator.text

    assert client.get("/static/css/nekowatch.css").status_code == 200
    logener_js = client.get("/static/js/logener.js")
    assert logener_js.status_code == 200
    assert "УДАЛИТЬ ВСЁ" in logener_js.text
    assert client.get("/static/js/dashboard.js").status_code == 200

    board = client.get("/api/v1/status/board")
    assert board.status_code == 200
    payload = board.json()
    assert "sources" in payload and "users" in payload

    demo = client.get("/api/v1/status/board?demo=true")
    assert demo.status_code == 200
    assert demo.json()["demo"] is True
    assert len(demo.json()["sources"]) >= 4


def test_full_reset_requires_confirm_and_wipes(seeded_client: TestClient) -> None:
    before = seeded_client.get("/api/v1/logs", params={"limit": 1}).json()
    assert before["total"] > 0

    denied = seeded_client.post("/logener/full-reset", json={"confirm": "nope"})
    assert denied.status_code == 400

    ok = seeded_client.post("/logener/full-reset", json={"confirm": "УДАЛИТЬ ВСЁ"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["log_file_size"] == 0
    assert body["wiped"]["alerts"] >= 1

    after = seeded_client.get("/api/v1/logs", params={"limit": 1}).json()
    assert after["total"] == 0

    board = seeded_client.get("/api/v1/status/board").json()
    assert board["sources"] == []
    assert board["users"] == []
