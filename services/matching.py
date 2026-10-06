"""In-memory evaluation of a :class:`LogFilter`.

The live WebSocket feed cannot round-trip to SQLite for every event it pushes,
so filters are evaluated in process. Semantics mirror
:func:`repositories.filters.build_where` — same OR-within-field,
AND-across-field behaviour, same ATT&CK parent matching — so a filter produces
consistent results whether it is applied to the stored history or to the live
tail.
"""

from __future__ import annotations

from domain.models import LogRecord
from domain.queries import LogFilter


def _matches_list(value: str | None, allowed: list[str]) -> bool:
    """Whether ``value`` is in ``allowed`` (empty ``allowed`` matches all)."""
    if not allowed:
        return True
    return value is not None and value in allowed


def _matches_mitre(stored: list[str], wanted: list[str], parents: bool) -> bool:
    """ATT&CK matching, optionally treating parent techniques as wildcards."""
    if not wanted:
        return True
    for target in wanted:
        for value in stored:
            if value == target:
                return True
            if parents and "." not in target and value.split(".", 1)[0] == target:
                return True
    return False


def record_matches(record: LogRecord, log_filter: LogFilter) -> bool:
    """Evaluate a filter against a single record.

    Args:
        record: The event to test.
        log_filter: Criteria to apply.

    Returns:
        ``True`` when the record satisfies every active criterion.
    """
    if log_filter.time_from and record.timestamp < log_filter.time_from:
        return False
    if log_filter.time_to and record.timestamp > log_filter.time_to:
        return False

    if log_filter.severities and record.severity not in log_filter.severities:
        return False

    level = record.rule_level
    if log_filter.min_level is not None:
        if level is None or level < log_filter.min_level:
            return False
    if log_filter.max_level is not None:
        if level is None or level > log_filter.max_level:
            return False

    if not _matches_list(record.rule_id, log_filter.rule_ids):
        return False
    if not _matches_list(record.alert_id, log_filter.alert_ids):
        return False
    if not _matches_list(record.src_ip, log_filter.src_ips):
        return False
    if not _matches_list(record.dst_ip, log_filter.dst_ips):
        return False
    if not _matches_list(record.user_name, log_filter.users):
        return False
    if not _matches_list(record.service, log_filter.services):
        return False
    if not _matches_list(record.log_level, log_filter.log_levels):
        return False

    if log_filter.triage_statuses and record.triage.status not in log_filter.triage_statuses:
        return False

    if log_filter.agents:
        if not (
            _matches_list(record.agent_id, log_filter.agents)
            or _matches_list(record.agent_name, log_filter.agents)
        ):
            return False

    if log_filter.groups and not any(
        group in record.rule_groups for group in log_filter.groups
    ):
        return False

    if not _matches_mitre(record.mitre_tactics, log_filter.mitre_tactics, parents=False):
        return False
    if not _matches_mitre(
        record.mitre_techniques, log_filter.mitre_techniques, parents=True
    ):
        return False

    if log_filter.q and not _matches_text(record, log_filter.q):
        return False

    return True


def _matches_text(record: LogRecord, query: str) -> bool:
    """Case-insensitive AND-of-terms search over the record's searchable text."""
    haystack = " ".join(
        part
        for part in (
            record.message,
            record.rule_description,
            record.rule_id,
            record.user_name,
            record.src_ip,
            record.dst_ip,
            record.service,
            record.agent_name,
            record.location,
            record.device_fingerprint,
            record.country,
            record.recipient,
            " ".join(record.rule_groups),
            " ".join(record.mitre_techniques),
        )
        if part
    ).lower()
    return all(term.lower() in haystack for term in query.split())
