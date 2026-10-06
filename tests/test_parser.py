"""Parser tests: malformed input, timestamps, enrichment and normalisation."""

from __future__ import annotations

import json

from domain.models import Severity
from services.parser import AlertParser
from tests.conftest import make_alert


def test_parses_wazuh_alert_into_normalised_record(parser: AlertParser) -> None:
    parsed = parser.parse_line(json.dumps(make_alert()))

    assert parsed is not None
    record, raw = parsed
    assert record.rule_id == "5712"
    assert record.rule_level == 10
    assert record.severity is Severity.HIGH
    assert record.src_ip == "185.220.101.44"
    assert record.dst_ip == "10.0.0.5"
    assert record.user_name == "alice"
    assert record.service == "sshd"
    assert record.agent_name == "bank-core-01"
    assert record.log_level == "WARN"
    assert json.loads(raw)["rule"]["id"] == "5712"


def test_full_log_payload_is_decoded_and_message_extracted(parser: AlertParser) -> None:
    alert = make_alert(description="Authentication failed for alice")
    record, _ = parser.parse_line(json.dumps(alert))

    assert "Authentication failed" in (record.message or "")
    assert record.device_fingerprint == "fp-1234"


def test_mitre_enrichment_maps_rule_to_technique(parser: AlertParser) -> None:
    record, _ = parser.parse_line(json.dumps(make_alert(rule_id="5712")))

    assert "T1110" in record.mitre_techniques
    assert "TA0006" in record.mitre_tactics


def test_severity_buckets_follow_wazuh_levels(parser: AlertParser) -> None:
    levels = {3: Severity.LOW, 7: Severity.MEDIUM, 10: Severity.HIGH, 14: Severity.CRITICAL}
    for level, expected in levels.items():
        record, _ = parser.parse_line(json.dumps(make_alert(level=level)))
        assert record.severity is expected, level


def test_blank_and_malformed_lines_are_rejected_without_raising(
    parser: AlertParser,
) -> None:
    assert parser.parse_line("") is None
    assert parser.parse_line("   \n") is None
    assert parser.parse_line("{not json") is None
    assert parser.parse_line("[1, 2, 3]") is None
    assert parser.errors >= 2  # blank lines are skipped, not counted as errors


def test_partial_alert_still_yields_a_record(parser: AlertParser) -> None:
    parsed = parser.parse_line(json.dumps({"rule": {"level": 12}}))

    assert parsed is not None
    record, _ = parsed
    assert record.severity is Severity.CRITICAL
    assert record.timestamp is not None  # falls back to ingestion time


def test_timestamp_formats_are_all_understood(parser: AlertParser) -> None:
    stamps = [
        "2026-07-28T12:00:00Z",
        "2026-07-28T12:00:00.123456+0000",
        "2026-07-28 12:00:00",
        "2026-07-28T12:00:00+03:00",
    ]
    for stamp in stamps:
        alert = make_alert()
        alert["timestamp"] = stamp
        record, _ = parser.parse_line(json.dumps(alert))
        assert record.timestamp.tzinfo is not None, stamp


def test_counters_track_success_and_failure(parser: AlertParser) -> None:
    parser.parse_line(json.dumps(make_alert()))
    parser.parse_line("{broken")

    assert parser.parsed == 1
    assert parser.errors == 1

    parser.reset()
    assert (parser.parsed, parser.errors) == (0, 0)


def test_ecs_projection_carries_key_fields(parser: AlertParser) -> None:
    record, _ = parser.parse_line(json.dumps(make_alert()))
    ecs = record.to_ecs()

    assert ecs["event"]["severity"] == 10
    assert ecs["source"]["ip"] == "185.220.101.44"
    assert ecs["rule"]["id"] == "5712"
    assert "T1110" in json.dumps(ecs["threat"])


def test_flat_dict_is_csv_friendly(parser: AlertParser) -> None:
    record, _ = parser.parse_line(json.dumps(make_alert()))
    flat = record.to_flat_dict()

    assert all(not isinstance(value, (dict, list)) for value in flat.values())
    assert flat["rule_id"] == "5712"
