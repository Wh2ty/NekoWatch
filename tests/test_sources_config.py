"""Tests for config/sources.yaml loading and plain-text alerts.log parsing."""

from __future__ import annotations

from pathlib import Path

from core.sources_config import load_sources_config
from services.parser import AlertParser, PlainAlertAssembler


def test_load_sources_config_active(tmp_path: Path) -> None:
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        """
active:
  - alerts_json
sources:
  alerts_json:
    path: /var/ossec/logs/alerts/alerts.json
    format: ndjson
    description: Wazuh JSON
  archives_json:
    path: /var/ossec/logs/archives/archives.json
    format: ndjson
""",
        encoding="utf-8",
    )
    sources = load_sources_config(cfg)
    assert len(sources) == 1
    assert sources[0].name == "alerts_json"
    assert sources[0].format == "ndjson"
    assert str(sources[0].path).replace("\\", "/").endswith(
        "/var/ossec/logs/alerts/alerts.json"
    )


def test_plain_assembler_and_parser() -> None:
    block = (
        "** Alert 1587490736.163684: - authentication_failed,sshd,\n"
        "2020 Apr 21 17:38:56 host-1->/var/log/auth.log\n"
        "Rule: 5712 (level 10) -> 'sshd: authentication failed.'\n"
        "Src IP: 185.220.101.44\n"
        "User: root\n"
        "Apr 21 17:38:56 host-1 sshd[1]: Failed password for root from 185.220.101.44\n"
        "\n"
    )
    assembler = PlainAlertAssembler()
    completed: list[str] = []
    for line in block.splitlines(keepends=True):
        completed.extend(assembler.feed(line))
    assert len(completed) == 1

    parser = AlertParser()
    parsed = parser.parse_line(completed[0], format="plain")
    assert parsed is not None
    record, _raw = parsed
    assert record.rule_id == "5712"
    assert record.rule_level == 10
    assert record.severity.value == "high"
    assert record.src_ip == "185.220.101.44"
    assert record.user_name == "root"
