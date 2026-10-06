"""Unit + API tests for custom correlation rules."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from domain.models import LogRecord, Severity, TriageInfo, TriageStatus
from domain.rules import (
    CorrelationRuleCreate,
    CorrelationRuleOut,
    RuleField,
    RuleGroupBy,
    RuleOperator,
)
from services.rule_engine import condition_matches


def _record(**overrides) -> LogRecord:
    base = dict(
        seq=1,
        timestamp=datetime.now(timezone.utc),
        rule_id="5712",
        rule_level=8,
        rule_description="sshd: authentication failed",
        severity=Severity.HIGH,
        src_ip="10.0.0.8",
        dst_ip="10.10.1.11",
        user_name="alice",
        agent_id="001",
        agent_name="bank-core-01",
        service="sshd",
        message="Failed password for alice",
        triage=TriageInfo(status=TriageStatus.NEW),
    )
    base.update(overrides)
    return LogRecord(**base)


def _rule_out(**overrides) -> CorrelationRuleOut:
    now = datetime.now(timezone.utc)
    data = dict(
        id=1,
        name="test",
        field=RuleField.SEVERITY,
        operator=RuleOperator.EQ,
        value="high",
        window_seconds=60,
        threshold=1,
        group_by=RuleGroupBy.NONE,
        severity="high",
        cooldown_seconds=0,
        created_at=now,
        updated_at=now,
    )
    data.update(overrides)
    return CorrelationRuleOut(**data)


def test_condition_matches_eq_contains_in() -> None:
    record = _record()
    assert condition_matches(record, _rule_out())
    assert condition_matches(
        record,
        _rule_out(
            field=RuleField.RULE_ID,
            operator=RuleOperator.IN,
            value="5710,5712,5752",
        ),
    )
    assert condition_matches(
        record,
        _rule_out(
            field=RuleField.MESSAGE,
            operator=RuleOperator.CONTAINS,
            value="failed",
        ),
    )
    assert not condition_matches(record, _rule_out(value="critical"))


@pytest.mark.asyncio
async def test_rule_engine_fires_threshold(tmp_path) -> None:
    from repositories.rules_repo import RulesRepository
    from repositories.sqlalchemy_repo import SqlAlchemyLogRepository
    from repositories.status_repo import StatusRepository
    from services.rule_engine import RuleEngine

    repo = SqlAlchemyLogRepository(tmp_path / "rules.db")
    await repo.initialize()
    rules_repo = RulesRepository(repo.database)
    status_repo = StatusRepository(repo.database)
    engine = RuleEngine(rules_repo, status_repo)
    await rules_repo.create(
        CorrelationRuleCreate(
            name="auth-burst",
            field=RuleField.RULE_ID,
            operator=RuleOperator.EQ,
            value="5712",
            window_seconds=60,
            threshold=3,
            group_by=RuleGroupBy.SRC_IP,
            severity="high",
            cooldown_seconds=0,
            enabled=True,
        )
    )
    await engine.reload()

    records = [_record(seq=i, src_ip="1.2.3.4") for i in range(1, 4)]
    hits = await engine.evaluate_records(records)
    assert len(hits) == 1
    assert hits[0].match_count >= 3
    assert hits[0].rule_name == "auth-burst"

    notifs = await status_repo.list_notifications(limit=10)
    assert any(n.kind == "correlation_rule" for n in notifs)
    await repo.close()


def test_rules_api_crud_and_page_button(client: TestClient) -> None:
    listed = client.get("/api/v1/rules")
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["total"] >= 1  # seeded defaults
    assert "catalogue" in payload
    assert payload["catalogue"]["fields"]

    created = client.post(
        "/api/v1/rules",
        json={
            "name": "UI mock rule",
            "description": "from test",
            "enabled": True,
            "field": "user_name",
            "operator": "eq",
            "value": "bob",
            "window_seconds": 30,
            "threshold": 2,
            "group_by": "src_ip",
            "severity": "medium",
            "cooldown_seconds": 10,
        },
    )
    assert created.status_code == 201, created.text
    rule_id = created.json()["id"]

    patched = client.patch(
        f"/api/v1/rules/{rule_id}",
        json={"threshold": 4, "enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["threshold"] == 4
    assert patched.json()["enabled"] is False

    enabled = client.post(f"/api/v1/rules/{rule_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    page = client.get("/")
    assert page.status_code == 200
    assert "Изменение правил" in page.text
    assert "rules-modal" in page.text
    assert "rules-form" in page.text

    deleted = client.delete(f"/api/v1/rules/{rule_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/rules/{rule_id}").status_code == 404
