"""ORM ↔ domain conversions and small helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from db.models import Alert
from domain.models import LogRecord, Severity, TriageInfo, TriageStatus


def load_json_list(value: Any) -> list[str]:
    """Decode a JSON array column into a list of strings."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v) for v in decoded] if isinstance(decoded, Iterable) else []


def dump_json_list(values: list[str] | None) -> str:
    """Encode a string list as a JSON array column."""
    return json.dumps(values or [], ensure_ascii=False)


def alert_to_record(row: Alert) -> LogRecord:
    """Rebuild a :class:`LogRecord` from an ORM ``Alert``."""
    triage = TriageInfo(
        status=TriageStatus(row.triage_status or "new"),
        analyst=row.triage_analyst,
        note=row.triage_note,
        updated_at=(
            datetime.fromisoformat(row.triage_updated_at)
            if row.triage_updated_at
            else None
        ),
    )
    return LogRecord(
        seq=int(row.seq),
        alert_id=row.alert_id,
        timestamp=datetime.fromtimestamp(float(row.ts_epoch), tz=timezone.utc),
        rule_id=row.rule_id,
        rule_level=row.rule_level,
        rule_description=row.rule_description,
        rule_groups=load_json_list(row.rule_groups),
        rule_firedtimes=row.rule_firedtimes,
        rule_mail=bool(row.rule_mail),
        severity=Severity(row.severity or "low"),
        agent_id=row.agent_id,
        agent_name=row.agent_name,
        agent_ip=row.agent_ip,
        manager_name=row.manager_name,
        decoder_name=row.decoder_name,
        program_name=row.program_name,
        hostname=row.hostname,
        location=row.location,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        user_name=row.user_name,
        service=row.service,
        log_level=row.log_level,
        device_fingerprint=row.device_fingerprint,
        message=row.message,
        amount=row.amount,
        currency=row.currency,
        recipient=row.recipient,
        country=row.country,
        prev_country=row.prev_country,
        failed_attempts=row.failed_attempts,
        window_seconds=row.window_seconds,
        expected_balance=row.expected_balance,
        actual_balance=row.actual_balance,
        mitre_tactics=load_json_list(row.mitre_tactics),
        mitre_techniques=load_json_list(row.mitre_techniques),
        triage=triage,
    )


def record_to_alert(record: LogRecord, raw: str) -> Alert:
    """Flatten a domain record into an ORM ``Alert`` (caller sets ``seq``)."""
    return Alert(**record_to_alert_values(record, raw))


def record_to_alert_values(record: LogRecord, raw: str) -> dict:
    """Column dict for Core ``insert(Alert)`` bulk writes."""
    return {
        "seq": record.seq,
        "alert_id": record.alert_id,
        "ts": record.timestamp.isoformat(),
        "ts_epoch": record.epoch,
        "rule_id": record.rule_id,
        "rule_level": record.rule_level,
        "rule_description": record.rule_description,
        "rule_groups": dump_json_list(record.rule_groups),
        "rule_firedtimes": record.rule_firedtimes,
        "rule_mail": bool(record.rule_mail),
        "severity": record.severity.value,
        "agent_id": record.agent_id,
        "agent_name": record.agent_name,
        "agent_ip": record.agent_ip,
        "manager_name": record.manager_name,
        "decoder_name": record.decoder_name,
        "program_name": record.program_name,
        "hostname": record.hostname,
        "location": record.location,
        "src_ip": record.src_ip,
        "dst_ip": record.dst_ip,
        "user_name": record.user_name,
        "service": record.service,
        "log_level": record.log_level,
        "device_fingerprint": record.device_fingerprint,
        "message": record.message,
        "amount": record.amount,
        "currency": record.currency,
        "recipient": record.recipient,
        "country": record.country,
        "prev_country": record.prev_country,
        "failed_attempts": record.failed_attempts,
        "window_seconds": record.window_seconds,
        "expected_balance": record.expected_balance,
        "actual_balance": record.actual_balance,
        "mitre_tactics": dump_json_list(record.mitre_tactics),
        "mitre_techniques": dump_json_list(record.mitre_techniques),
        "raw": raw,
        "triage_status": record.triage.status.value,
        "triage_analyst": record.triage.analyst,
        "triage_note": record.triage.note,
        "triage_updated_at": (
            record.triage.updated_at.isoformat() if record.triage.updated_at else None
        ),
    }
