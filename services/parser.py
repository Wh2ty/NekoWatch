"""Parse Logener/Wazuh NDJSON lines and Wazuh ``alerts.log`` text blocks.

The parser is deliberately forgiving: a malformed or half-written line (the
generator appends while we tail, so the last line can be incomplete) must never
break ingestion. Bad lines increment :attr:`AlertParser.errors` and are skipped.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from core import mitre
from domain.models import (
    BankEventPayload,
    LogRecord,
    Severity,
    WazuhAlert,
)

logger = logging.getLogger("nekowatch.parser")

#: Fallback timestamp layouts tried when ISO-8601 parsing fails.
_TIMESTAMP_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)

#: Wazuh classic ``alerts.log`` layouts.
_RULE_RE = re.compile(
    r"Rule:\s*(\d+)\s*\(level\s*(\d+)\)\s*->\s*'([^']*)'",
    re.IGNORECASE,
)
_SRC_IP_RE = re.compile(r"Src IP:\s*(\S+)", re.IGNORECASE)
_DST_IP_RE = re.compile(r"Dst IP:\s*(\S+)", re.IGNORECASE)
_USER_RE = re.compile(r"(?:Src )?User:\s*(\S+)", re.IGNORECASE)
_ALERT_ID_RE = re.compile(r"\*\*\s*Alert\s+(\d+\.\d+)", re.IGNORECASE)
_LOCATION_RE = re.compile(
    r"^(\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.+?)(?:->(.+))?$",
    re.MULTILINE,
)
_PLAIN_TS_FORMATS: tuple[str, ...] = (
    "%Y %b %d %H:%M:%S",
    "%Y %B %d %H:%M:%S",
)


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse a Wazuh/Logener timestamp into timezone-aware UTC.

    Handles the two shapes Logener emits — ``...123+0000`` on the alert and
    ``...123Z`` on the nested payload — plus a few common variants.

    Args:
        value: Raw timestamp string, possibly ``None``.

    Returns:
        A UTC datetime, or ``None`` when the value is missing/unparseable.
    """
    if not value:
        return None
    text = value.strip()
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None

    if parsed is None:
        for fmt in _TIMESTAMP_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue

    if parsed is None:
        for fmt in _PLAIN_TS_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue

    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first(*values: Any) -> Any:
    """Return the first value that is neither ``None`` nor an empty string."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


class PlainAlertAssembler:
    """Accumulate multi-line Wazuh ``alerts.log`` records into complete blocks.

    A new block starts at ``** Alert ...``. The previous block is emitted when
    the next header arrives or when a trailing blank line closes the record.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf: list[str] = []

    def feed(self, line: str) -> list[str]:
        """Push one line; return zero or more completed alert texts."""
        completed: list[str] = []
        if line.startswith("** Alert") or line.startswith("**Alert"):
            if self._buf:
                completed.append("".join(self._buf).rstrip("\n") + "\n")
            self._buf = [line]
            return completed

        if not self._buf:
            # Orphan line before the first header — ignore.
            return completed

        self._buf.append(line)
        if line.strip() == "" and len(self._buf) > 2:
            completed.append("".join(self._buf).rstrip("\n") + "\n")
            self._buf = []
        return completed

    def flush(self) -> str | None:
        """Emit any buffered incomplete alert (e.g. on EOF / stop)."""
        if not self._buf:
            return None
        text = "".join(self._buf).rstrip("\n") + "\n"
        self._buf = []
        return text


class AlertParser:
    """Stateless-ish converter from raw alert lines to normalized records.

    The only state kept is a pair of counters, so a single instance can be
    shared by the ingestion pipeline to report parse health.
    """

    def __init__(self) -> None:
        self.parsed: int = 0
        self.errors: int = 0

    def reset(self) -> None:
        """Zero the parse counters."""
        self.parsed = 0
        self.errors = 0

    def parse_line(
        self, line: str, *, format: str = "ndjson"
    ) -> tuple[LogRecord, str] | None:
        """Parse one NDJSON line or feed a complete plain-text alert block.

        Args:
            line: A single line from an NDJSON file, or a full ``alerts.log``
                block when ``format='plain'``.
            format: ``ndjson`` (default) or ``plain``.
        """
        if format == "plain":
            return self.parse_plain_block(line)
        return self._parse_ndjson_line(line)

    def _parse_ndjson_line(self, line: str) -> tuple[LogRecord, str] | None:
        """Parse one NDJSON line."""
        raw = (line or "").strip()
        if not raw or raw.startswith("#"):
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self.errors += 1
            logger.debug("skipped_malformed_line", extra={"length": len(raw)})
            return None
        if not isinstance(payload, dict):
            self.errors += 1
            return None
        return self.parse_dict(payload, raw)

    def parse_plain_block(self, block: str) -> tuple[LogRecord, str] | None:
        """Parse a multi-line Wazuh ``alerts.log`` alert into a :class:`LogRecord`."""
        text = (block or "").strip()
        if not text:
            return None

        rule_match = _RULE_RE.search(text)
        if not rule_match:
            self.errors += 1
            logger.debug("skipped_plain_alert_no_rule")
            return None

        rule_id, level_s, description = rule_match.groups()
        try:
            level = int(level_s)
        except ValueError:
            level = 0

        alert_id_match = _ALERT_ID_RE.search(text)
        alert_id = alert_id_match.group(1) if alert_id_match else None

        loc_match = _LOCATION_RE.search(text)
        ts_raw = loc_match.group(1) if loc_match else None
        hostname = (loc_match.group(2) or "").strip() if loc_match else None
        location = (loc_match.group(3) or "").strip() if loc_match else None

        groups: list[str] = []
        header = text.splitlines()[0] if text else ""
        if " - " in header:
            groups_part = header.split(" - ", 1)[1].rstrip(",")
            groups = [g.strip() for g in groups_part.split(",") if g.strip()]

        # Prefer the last non-empty line after the Rule line as full_log body.
        body_lines = [
            ln for ln in text.splitlines() if ln.strip() and not ln.startswith("**")
        ]
        full_log = body_lines[-1] if body_lines else text

        payload: dict[str, Any] = {
            "id": alert_id,
            "timestamp": None,
            "location": location or hostname,
            "full_log": full_log,
            "rule": {
                "id": rule_id,
                "level": level,
                "description": description,
                "groups": groups,
            },
            "agent": {"name": hostname},
            "predecoder": {"hostname": hostname, "timestamp": ts_raw},
            "data": {
                "srcip": _match_group(_SRC_IP_RE, text),
                "dstip": _match_group(_DST_IP_RE, text),
                "user": _match_group(_USER_RE, text),
            },
        }
        # Attach a synthetic ISO timestamp for WazuhAlert when we can parse it.
        parsed_ts = parse_timestamp(ts_raw)
        if parsed_ts is not None:
            payload["timestamp"] = parsed_ts.isoformat().replace("+00:00", "Z")

        return self.parse_dict(payload, text)

    def parse_dict(
        self, payload: dict[str, Any], raw: str | None = None
    ) -> tuple[LogRecord, str] | None:
        """Parse an already-decoded alert dictionary."""
        try:
            alert = WazuhAlert.model_validate(payload)
        except Exception:  # noqa: BLE001 - never let one alert stop the stream
            self.errors += 1
            logger.debug("skipped_invalid_alert", exc_info=True)
            return None

        record = self.to_record(alert)
        self.parsed += 1
        return record, raw if raw is not None else json.dumps(
            payload, ensure_ascii=False
        )

    def to_record(self, alert: WazuhAlert) -> LogRecord:
        """Normalize a validated :class:`WazuhAlert` into a :class:`LogRecord`.

        Field precedence is ``alert.data`` first (decoder output), then the
        nested ``full_log`` payload, mirroring how Wazuh itself layers decoded
        fields over the original event.
        """
        event: BankEventPayload = alert.decode_full_log()
        data = alert.data

        timestamp = (
            parse_timestamp(alert.timestamp)
            or parse_timestamp(alert.predecoder.timestamp)
            or parse_timestamp(event.timestamp)
            or datetime.now(timezone.utc)
        )

        level = alert.rule.level
        fingerprint = _first(data.device_fingerprint, event.device_fingerprint)
        techniques = mitre.techniques_for(
            alert.rule.id,
            alert.rule.groups,
            device_fingerprint=fingerprint,
        )

        return LogRecord(
            alert_id=alert.id,
            timestamp=timestamp,
            rule_id=alert.rule.id,
            rule_level=level,
            rule_description=alert.rule.description,
            rule_groups=list(alert.rule.groups),
            rule_firedtimes=alert.rule.firedtimes,
            rule_mail=bool(alert.rule.mail),
            severity=Severity.from_level(level),
            agent_id=alert.agent.id,
            agent_name=alert.agent.name,
            agent_ip=alert.agent.ip,
            manager_name=alert.manager.name,
            decoder_name=alert.decoder.name,
            program_name=_first(alert.predecoder.program_name, event.service),
            hostname=_first(alert.predecoder.hostname, alert.agent.name),
            location=alert.location,
            src_ip=_first(data.srcip, event.ip),
            dst_ip=_first(data.dstip, alert.agent.ip),
            user_name=_first(data.user, event.user_id),
            service=_first(data.service, event.service),
            log_level=_normalize_log_level(_first(data.level, event.level)),
            device_fingerprint=fingerprint,
            message=_first(data.message, event.message),
            amount=_first(data.amount, event.amount),
            currency=_first(data.currency, event.currency),
            recipient=_first(data.recipient, event.recipient),
            country=event.country,
            prev_country=event.prev_country,
            failed_attempts=event.failed_attempts,
            window_seconds=event.window_seconds,
            expected_balance=event.expected_balance,
            actual_balance=event.actual_balance,
            mitre_tactics=mitre.tactic_ids(techniques),
            mitre_techniques=mitre.technique_ids(techniques),
        )

    def iter_lines(self, lines: Iterable[str]) -> Iterator[tuple[LogRecord, str]]:
        """Lazily parse an iterable of lines, skipping unparseable ones.

        Generator-based so a multi-gigabyte file can be processed with a
        constant memory footprint.
        """
        for line in lines:
            parsed = self.parse_line(line)
            if parsed is not None:
                yield parsed


def _match_group(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _normalize_log_level(value: Any) -> str | None:
    """Upper-case the application log level (``info`` -> ``INFO``)."""
    if value is None:
        return None
    text = str(value).strip().upper()
    return text or None
