"""Translate a :class:`~domain.queries.LogFilter` into SQLAlchemy predicates.

Every read path — search, analytics, correlation, export — shares this builder
so a chart, a table and a CSV download always describe the same selection.
All values are bound parameters; nothing is interpolated into SQL text.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import ColumnElement, Select, and_, exists, func, or_, select, true
from sqlalchemy.sql.elements import ColumnElement as SQLColumnElement

from db.models import Alert, AlertMitre
from domain.queries import LogFilter

#: Columns eligible for generic ``top N`` aggregation.
AGGREGATABLE_COLUMNS: frozenset[str] = frozenset(
    {
        "src_ip",
        "dst_ip",
        "user_name",
        "service",
        "agent_name",
        "agent_id",
        "hostname",
        "program_name",
        "decoder_name",
        "log_level",
        "severity",
        "rule_id",
        "location",
        "device_fingerprint",
        "currency",
        "recipient",
        "country",
    }
)

#: Map aggregatable / groupable names onto ORM columns.
ALERT_COLUMNS: dict[str, Any] = {
    "src_ip": Alert.src_ip,
    "dst_ip": Alert.dst_ip,
    "agent_ip": Alert.agent_ip,
    "user_name": Alert.user_name,
    "service": Alert.service,
    "agent_name": Alert.agent_name,
    "agent_id": Alert.agent_id,
    "hostname": Alert.hostname,
    "program_name": Alert.program_name,
    "decoder_name": Alert.decoder_name,
    "log_level": Alert.log_level,
    "severity": Alert.severity,
    "rule_id": Alert.rule_id,
    "rule_description": Alert.rule_description,
    "rule_level": Alert.rule_level,
    "location": Alert.location,
    "device_fingerprint": Alert.device_fingerprint,
    "currency": Alert.currency,
    "recipient": Alert.recipient,
    "country": Alert.country,
}


def escape_fts_query(query: str) -> str:
    """Turn free-text input into a safe FTS5 MATCH expression."""
    terms = [t for t in query.split() if t]
    quoted = ['"' + t.replace('"', '""') + '"' for t in terms]
    return " AND ".join(quoted)


def build_predicate(
    log_filter: LogFilter,
    *,
    fts_enabled: bool = True,
) -> ColumnElement[bool]:
    """Build a SQLAlchemy boolean expression for the filter.

    Returns ``true()`` for an empty filter so callers can always
    ``.where(predicate)`` without special-casing.
    """
    clauses: list[ColumnElement[bool]] = []

    if log_filter.time_from is not None:
        clauses.append(Alert.ts_epoch >= log_filter.time_from.timestamp())
    if log_filter.time_to is not None:
        clauses.append(Alert.ts_epoch <= log_filter.time_to.timestamp())

    if log_filter.severities:
        clauses.append(Alert.severity.in_([s.value for s in log_filter.severities]))

    if log_filter.min_level is not None:
        clauses.append(Alert.rule_level >= log_filter.min_level)
    if log_filter.max_level is not None:
        clauses.append(Alert.rule_level <= log_filter.max_level)

    simple: tuple[tuple[Any, list[str]], ...] = (
        (Alert.rule_id, log_filter.rule_ids),
        (Alert.alert_id, log_filter.alert_ids),
        (Alert.src_ip, log_filter.src_ips),
        (Alert.dst_ip, log_filter.dst_ips),
        (Alert.user_name, log_filter.users),
        (Alert.service, log_filter.services),
        (Alert.log_level, log_filter.log_levels),
    )
    for column, values in simple:
        if values:
            clauses.append(column.in_(values))

    if log_filter.triage_statuses:
        clauses.append(
            Alert.triage_status.in_([s.value for s in log_filter.triage_statuses])
        )

    if log_filter.agents:
        clauses.append(
            or_(
                Alert.agent_id.in_(log_filter.agents),
                Alert.agent_name.in_(log_filter.agents),
            )
        )

    if log_filter.groups:
        clauses.append(
            or_(*[Alert.rule_groups.like(f'%"{group}"%') for group in log_filter.groups])
        )

    if log_filter.mitre_tactics:
        clauses.append(_mitre_exists("tactic_id", log_filter.mitre_tactics))

    if log_filter.mitre_techniques:
        clauses.append(_mitre_exists("technique_id", log_filter.mitre_techniques))

    if log_filter.q:
        text_clause = _full_text(log_filter.q, fts_enabled)
        if text_clause is not None:
            clauses.append(text_clause)

    if not clauses:
        return true()
    return and_(*clauses)


def apply_filter(
    stmt: Select[Any],
    log_filter: LogFilter,
    *,
    fts_enabled: bool = True,
) -> Select[Any]:
    """Attach the filter predicate to a SELECT statement."""
    return stmt.where(build_predicate(log_filter, fts_enabled=fts_enabled))


def _mitre_exists(column: str, values: list[str]) -> ColumnElement[bool]:
    """``EXISTS`` against ``alert_mitre``; parent techniques match sub-techniques."""
    attr = getattr(AlertMitre, column)
    matchers: list[ColumnElement[bool]] = []
    for value in values:
        if column == "technique_id" and "." not in value:
            matchers.append(or_(attr == value, attr.like(f"{value}.%")))
        else:
            matchers.append(attr == value)
            
    # Добавляем явную корреляцию только по Alert, изолируя AlertMitre
    return exists(
        select(1)
        .where(AlertMitre.seq == Alert.seq, or_(*matchers))
        .correlate(Alert)
    )



def _full_text(query: str, fts_enabled: bool) -> ColumnElement[bool] | None:
    """FTS5 MATCH when available, otherwise AND-ed ``LIKE`` scans."""
    if fts_enabled:
        match = escape_fts_query(query)
        if not match:
            return None
        # FTS5 virtual table is not an ORM entity — query it via text().
        from sqlalchemy import literal_column, text

        fts = (
            select(literal_column("rowid"))
            .select_from(text("alerts_fts"))
            .where(text("alerts_fts MATCH :fts_match").bindparams(fts_match=match))
        )
        return Alert.seq.in_(fts)

    terms = [t for t in query.split() if t]
    if not terms:
        return None
    per_term = []
    for term in terms:
        needle = f"%{term}%"
        per_term.append(
            or_(
                Alert.message.like(needle),
                Alert.rule_description.like(needle),
                Alert.raw.like(needle),
            )
        )
    return and_(*per_term)


# Backwards-compatible name used by older call sites / docs.
def build_where(
    log_filter: LogFilter,
    *,
    fts_enabled: bool = True,
    table_alias: str = "a",
) -> tuple[SQLColumnElement[bool], list[Any]]:
    """Compatibility wrapper — prefer :func:`build_predicate`.

    Returns ``(predicate, [])``; the empty params list is retained so call
    sites that previously unpacked ``(sql, params)`` keep compiling.
    """
    del table_alias  # ORM predicates already qualify columns.
    return build_predicate(log_filter, fts_enabled=fts_enabled), []
