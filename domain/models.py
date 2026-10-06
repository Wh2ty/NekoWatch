"""Event models: the raw Wazuh envelope and NekoWatch's normalized log record.

Two layers live here:

``WazuhAlert``
    A faithful, permissive model of what Logener (and a real Wazuh manager)
    writes to the alerts file. Unknown fields are preserved.

``LogRecord``
    The normalized, flat event NekoWatch stores, filters and aggregates. It
    also knows how to render itself as Elastic Common Schema (ECS) via
    :meth:`LogRecord.to_ecs`, which is what analysts and downstream SIEM
    pipelines expect.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Wazuh rule levels run 0-15; these are the conventional SOC buckets.
_SEVERITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (3, "low"),
    (7, "medium"),
    (11, "high"),
    (15, "critical"),
)


class Severity(StrEnum):
    """Severity bucket derived from the Wazuh rule level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_level(cls, level: int | None) -> "Severity":
        """Map a Wazuh rule level (0-15) onto a severity bucket."""
        if level is None:
            return cls.LOW
        for ceiling, name in _SEVERITY_THRESHOLDS:
            if level <= ceiling:
                return cls(name)
        return cls.CRITICAL

    @property
    def rank(self) -> int:
        """Numeric ordering, useful for sorting and comparisons."""
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class TriageStatus(StrEnum):
    """Analyst workflow state of an alert."""

    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ExportFormat(StrEnum):
    """Supported export encodings."""

    CSV = "csv"
    JSON = "json"
    JSONL = "jsonl"


# --------------------------------------------------------------------------- #
# Raw Wazuh envelope
# --------------------------------------------------------------------------- #
class _Permissive(BaseModel):
    """Base for raw-alert models: keep unknown fields instead of dropping them."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class WazuhRule(_Permissive):
    """The ``rule`` block of a Wazuh alert."""

    id: str | None = None
    level: int | None = None
    description: str | None = None
    firedtimes: int | None = None
    mail: bool | None = None
    groups: list[str] = Field(default_factory=list)

    @field_validator("id", mode="before")
    @classmethod
    def _stringify_id(cls, value: Any) -> Any:
        """Wazuh rule ids are strings, but numeric ids appear in the wild."""
        return str(value) if isinstance(value, int) else value


class WazuhAgent(_Permissive):
    """The reporting agent."""

    id: str | None = None
    name: str | None = None
    ip: str | None = None


class WazuhManager(_Permissive):
    """The Wazuh manager that processed the alert."""

    name: str | None = None


class WazuhPredecoder(_Permissive):
    """Pre-decoding metadata (syslog program name, hostname, timestamp)."""

    program_name: str | None = None
    timestamp: str | None = None
    hostname: str | None = None


class WazuhDecoder(_Permissive):
    """The decoder that parsed the original log line."""

    name: str | None = None


class WazuhData(_Permissive):
    """The ``data`` block: decoder-extracted fields."""

    srcip: str | None = None
    dstip: str | None = None
    user: str | None = None
    service: str | None = None
    level: str | None = None
    device_fingerprint: str | None = None
    message: str | None = None
    amount: float | None = None
    currency: str | None = None
    recipient: str | None = None


class BankEventPayload(_Permissive):
    """The application event Logener nests, JSON-encoded, inside ``full_log``."""

    timestamp: str | None = None
    service: str | None = None
    level: str | None = None
    user_id: str | None = None
    ip: str | None = None
    device_fingerprint: str | None = None
    message: str | None = None
    amount: float | None = None
    currency: str | None = None
    recipient: str | None = None
    country: str | None = None
    prev_country: str | None = None
    expected_balance: float | None = None
    actual_balance: float | None = None
    failed_attempts: int | None = None
    window_seconds: int | None = None


class WazuhAlert(_Permissive):
    """A complete Wazuh-format alert as emitted by Logener."""

    id: str | None = None
    timestamp: str | None = None
    location: str | None = None
    full_log: str | None = None
    rule: WazuhRule = Field(default_factory=WazuhRule)
    agent: WazuhAgent = Field(default_factory=WazuhAgent)
    manager: WazuhManager = Field(default_factory=WazuhManager)
    predecoder: WazuhPredecoder = Field(default_factory=WazuhPredecoder)
    decoder: WazuhDecoder = Field(default_factory=WazuhDecoder)
    data: WazuhData = Field(default_factory=WazuhData)

    def decode_full_log(self) -> BankEventPayload:
        """Decode the nested ``full_log`` payload.

        Returns an empty payload when ``full_log`` is absent or is not JSON
        (a plain syslog string, which is what real Wazuh usually carries).
        """
        if not self.full_log:
            return BankEventPayload()
        try:
            decoded = json.loads(self.full_log)
        except (json.JSONDecodeError, TypeError):
            return BankEventPayload()
        if not isinstance(decoded, dict):
            return BankEventPayload()
        return BankEventPayload.model_validate(decoded)


# --------------------------------------------------------------------------- #
# Normalized record
# --------------------------------------------------------------------------- #
class TriageInfo(BaseModel):
    """Analyst triage state attached to a stored alert."""

    status: TriageStatus = TriageStatus.NEW
    analyst: str | None = None
    note: str | None = None
    updated_at: datetime | None = None


class LogRecord(BaseModel):
    """Normalized security event — the unit NekoWatch stores and queries."""

    model_config = ConfigDict(use_enum_values=False)

    seq: int = 0
    alert_id: str | None = None
    timestamp: datetime

    # -- rule ---------------------------------------------------------------
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    rule_firedtimes: int | None = None
    rule_mail: bool = False
    severity: Severity = Severity.LOW

    # -- infrastructure -----------------------------------------------------
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    manager_name: str | None = None
    decoder_name: str | None = None
    program_name: str | None = None
    hostname: str | None = None
    location: str | None = None

    # -- network / identity -------------------------------------------------
    src_ip: str | None = None
    dst_ip: str | None = None
    user_name: str | None = None
    service: str | None = None
    log_level: str | None = None
    device_fingerprint: str | None = None
    message: str | None = None

    # -- business context ---------------------------------------------------
    amount: float | None = None
    currency: str | None = None
    recipient: str | None = None
    country: str | None = None
    prev_country: str | None = None
    failed_attempts: int | None = None
    window_seconds: int | None = None
    expected_balance: float | None = None
    actual_balance: float | None = None

    # -- threat intel -------------------------------------------------------
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # -- workflow -----------------------------------------------------------
    triage: TriageInfo = Field(default_factory=TriageInfo)

    @field_validator("timestamp")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        """Normalize every timestamp to timezone-aware UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @property
    def epoch(self) -> float:
        """Event time as a POSIX timestamp (the indexed range-query column)."""
        return self.timestamp.timestamp()

    def to_ecs(self) -> dict[str, Any]:
        """Render the record as an Elastic Common Schema document.

        Field names follow ECS 8.x so exports can be shipped straight into
        Elasticsearch, OpenSearch or any ECS-aware pipeline.
        """
        doc: dict[str, Any] = {
            "@timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "message": self.message,
            "event": {
                "kind": "alert",
                "module": "wazuh",
                "dataset": "wazuh.alerts",
                "code": self.rule_id,
                "action": self.rule_description,
                "severity": self.rule_level,
                "id": self.alert_id,
                "sequence": self.seq,
            },
            "rule": {
                "id": self.rule_id,
                "name": self.rule_description,
                "ruleset": "logener",
                "category": self.rule_groups,
            },
            "observer": {
                "vendor": "Wazuh",
                "product": "Wazuh Manager",
                "name": self.manager_name,
                "type": "siem",
            },
            "agent": {"id": self.agent_id, "name": self.agent_name},
            "host": {"hostname": self.hostname, "ip": self.agent_ip},
            "source": {"ip": self.src_ip},
            "destination": {"ip": self.dst_ip},
            "user": {"name": self.user_name},
            "service": {"name": self.service},
            "log": {
                "level": self.log_level,
                "file": {"path": self.location},
                "logger": self.decoder_name,
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": self.mitre_tactics},
                "technique": {"id": self.mitre_techniques},
            },
            "nekowatch": {
                "severity": self.severity.value,
                "fired_times": self.rule_firedtimes,
                "mail_flagged": self.rule_mail,
                "device_fingerprint": self.device_fingerprint,
                "triage": {
                    "status": self.triage.status.value,
                    "analyst": self.triage.analyst,
                    "note": self.triage.note,
                },
            },
        }
        transaction = {
            "amount": self.amount,
            "currency": self.currency,
            "recipient": self.recipient,
            "country": self.country,
            "previous_country": self.prev_country,
            "failed_attempts": self.failed_attempts,
            "window_seconds": self.window_seconds,
            "expected_balance": self.expected_balance,
            "actual_balance": self.actual_balance,
        }
        populated = {k: v for k, v in transaction.items() if v is not None}
        if populated:
            doc["nekowatch"]["transaction"] = populated
        return doc

    def to_flat_dict(self) -> dict[str, Any]:
        """Flat, CSV-friendly projection of the record."""
        payload = self.model_dump(mode="json", exclude={"triage"})
        payload["rule_groups"] = ",".join(self.rule_groups)
        payload["mitre_tactics"] = ",".join(self.mitre_tactics)
        payload["mitre_techniques"] = ",".join(self.mitre_techniques)
        payload["triage_status"] = self.triage.status.value
        payload["triage_analyst"] = self.triage.analyst or ""
        payload["triage_note"] = self.triage.note or ""
        payload["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return payload


#: Column order used by CSV export (also the canonical flat field order).
CSV_COLUMNS: tuple[str, ...] = (
    "seq",
    "timestamp",
    "alert_id",
    "severity",
    "rule_level",
    "rule_id",
    "rule_description",
    "rule_groups",
    "log_level",
    "src_ip",
    "dst_ip",
    "user_name",
    "service",
    "agent_id",
    "agent_name",
    "agent_ip",
    "hostname",
    "program_name",
    "decoder_name",
    "manager_name",
    "location",
    "device_fingerprint",
    "message",
    "amount",
    "currency",
    "recipient",
    "country",
    "prev_country",
    "failed_attempts",
    "window_seconds",
    "expected_balance",
    "actual_balance",
    "mitre_tactics",
    "mitre_techniques",
    "rule_firedtimes",
    "rule_mail",
    "triage_status",
    "triage_analyst",
    "triage_note",
)


class LogRecordDetail(BaseModel):
    """Full drill-down view of a single alert."""

    record: LogRecord
    ecs: dict[str, Any]
    raw: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
