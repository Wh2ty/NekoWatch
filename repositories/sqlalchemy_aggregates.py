"""Aggregation queries via SQLAlchemy Core (dashboard charts)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import Integer, Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core import mitre
from db.models import Alert, AlertMitre
from domain.models import Severity
from domain.queries import (
    CorrelationGroup,
    FieldCount,
    IpCount,
    LogFilter,
    MitreBreakdown,
    MitreCount,
    OverviewResponse,
    RuleCount,
    SeverityCount,
    TimelinePoint,
    TriageSummary,
)
from repositories.filters import AGGREGATABLE_COLUMNS, ALERT_COLUMNS, apply_filter
from repositories.mapping import load_json_list

_IP_COLUMNS: frozenset[str] = frozenset({"src_ip", "dst_ip", "agent_ip"})
GROUPABLE_COLUMNS: frozenset[str] = AGGREGATABLE_COLUMNS | frozenset(
    {"rule_description", "rule_level"}
)


def _split_concat(value: Any, limit: int = 5) -> list[str]:
    if not value:
        return []
    return [p for p in str(value).split(",") if p][:limit]


def _percentage(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round(part * 100.0 / whole, 2)


def _as_int(value: Any) -> int:
    return int(value) if value is not None else 0


def _severity_sums() -> tuple[Any, ...]:
    return (
        func.sum(case((Alert.severity == "low", 1), else_=0)).label("low_count"),
        func.sum(case((Alert.severity == "medium", 1), else_=0)).label("medium_count"),
        func.sum(case((Alert.severity == "high", 1), else_=0)).label("high_count"),
        func.sum(case((Alert.severity == "critical", 1), else_=0)).label(
            "critical_count"
        ),
    )


class SqlAlchemyAggregatesMixin:
    """SQL aggregations shared by the analytics endpoints."""

    _fts_enabled: bool

    def _session(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def _filtered(self, stmt: Select[Any], log_filter: LogFilter) -> Select[Any]:
        return apply_filter(stmt, log_filter, fts_enabled=self._fts_enabled)

    async def timeline(
        self, log_filter: LogFilter, interval_seconds: int
    ) -> list[TimelinePoint]:
        interval = max(1, int(interval_seconds))
        bucket = (func.cast(Alert.ts_epoch / interval, Integer) * interval).label(
            "bucket"
        )
        stmt = self._filtered(
            select(bucket, func.count().label("total"), *_severity_sums())
            .group_by(bucket)
            .order_by(bucket),
            log_filter,
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [
            TimelinePoint(
                bucket=datetime.fromtimestamp(float(row["bucket"]), tz=timezone.utc),
                count=_as_int(row["total"]),
                low=_as_int(row["low_count"]),
                medium=_as_int(row["medium_count"]),
                high=_as_int(row["high_count"]),
                critical=_as_int(row["critical_count"]),
            )
            for row in rows
        ]

    async def severity_distribution(
        self, log_filter: LogFilter
    ) -> list[SeverityCount]:
        stmt = self._filtered(
            select(Alert.severity, func.count().label("total")).group_by(Alert.severity),
            log_filter,
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).all()
        counts = {str(severity): _as_int(total) for severity, total in rows}
        total = sum(counts.values())
        return [
            SeverityCount(
                severity=severity,
                count=counts.get(severity.value, 0),
                percentage=_percentage(counts.get(severity.value, 0), total),
            )
            for severity in sorted(Severity, key=lambda s: s.rank, reverse=True)
        ]

    async def top_rules(self, log_filter: LogFilter, limit: int = 10) -> list[RuleCount]:
        stmt = (
            self._filtered(
                select(
                    Alert.rule_id,
                    func.count().label("total"),
                    func.max(Alert.rule_level).label("level"),
                    func.max(Alert.rule_description).label("description"),
                    func.max(Alert.rule_groups).label("groups"),
                    func.max(Alert.mitre_techniques).label("techniques"),
                ).group_by(Alert.rule_id),
                log_filter,
            )
            .order_by(func.count().desc(), Alert.rule_id.asc())
            .limit(max(1, limit))
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [
            RuleCount(
                rule_id=row["rule_id"],
                description=row["description"],
                level=row["level"],
                severity=Severity.from_level(row["level"]),
                count=_as_int(row["total"]),
                groups=load_json_list(row["groups"]),
                mitre_techniques=load_json_list(row["techniques"]),
            )
            for row in rows
        ]

    async def top_ips(
        self, log_filter: LogFilter, column: str, limit: int = 10
    ) -> list[IpCount]:
        if column not in _IP_COLUMNS:
            raise ValueError(f"unsupported_ip_column:{column}")
        col = ALERT_COLUMNS[column]
        stmt = (
            self._filtered(
                select(
                    col.label("ip"),
                    func.count().label("total"),
                    func.count(func.distinct(Alert.user_name)).label("users"),
                    func.max(Alert.rule_level).label("max_level"),
                    func.sum(case((Alert.severity == "critical", 1), else_=0)).label(
                        "crit"
                    ),
                )
                .where(col.is_not(None), col != "")
                .group_by(col),
                log_filter,
            )
            .order_by(func.count().desc(), col.asc())
            .limit(max(1, limit))
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [
            IpCount(
                ip=str(row["ip"]),
                count=_as_int(row["total"]),
                unique_users=_as_int(row["users"]),
                max_level=row["max_level"],
                severity=Severity.from_level(row["max_level"]),
                critical_count=_as_int(row["crit"]),
            )
            for row in rows
        ]

    async def top_field(
        self, log_filter: LogFilter, column: str, limit: int = 10
    ) -> list[FieldCount]:
        if column not in AGGREGATABLE_COLUMNS:
            raise ValueError(f"unsupported_column:{column}")
        col = ALERT_COLUMNS[column]
        stmt = (
            self._filtered(
                select(col.label("key"), func.count().label("total"))
                .where(col.is_not(None), col != "")
                .group_by(col),
                log_filter,
            )
            .order_by(func.count().desc(), col.asc())
            .limit(max(1, limit))
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [
            FieldCount(key=str(row["key"]), count=_as_int(row["total"])) for row in rows
        ]

    async def mitre_breakdown(
        self, log_filter: LogFilter, limit: int = 20
    ) -> MitreBreakdown:
        capped = max(1, limit)
        join_base = apply_filter(
            select(AlertMitre.tactic_id, AlertMitre.technique_id, AlertMitre.seq).join(
                Alert, Alert.seq == AlertMitre.seq
            ),
            log_filter,
            fts_enabled=self._fts_enabled,
        )
        # ИСПРАВЛЕНИЕ 1: Изолируем подзапрос от автокорреляции
        subq = join_base.correlate(None).subquery()

        tactic_stmt = (
            select(
                subq.c.tactic_id.label("id"),
                func.count(func.distinct(subq.c.seq)).label("total"),
            )
            .group_by(subq.c.tactic_id)
            .order_by(func.count(func.distinct(subq.c.seq)).desc())
            .limit(capped)
        )
        tech_stmt = (
            select(
                subq.c.technique_id.label("id"),
                subq.c.tactic_id.label("tactic_id"),
                func.count(func.distinct(subq.c.seq)).label("total"),
            )
            .group_by(subq.c.technique_id, subq.c.tactic_id)
            .order_by(func.count(func.distinct(subq.c.seq)).desc())
            .limit(capped)
        )
        
        # ИСПРАВЛЕНИЕ 2: Явно разрешаем корреляцию только по таблице Alert для exists()
        untagged_stmt = self._filtered(
            select(func.count()).where(
                ~select(AlertMitre.seq)
                .where(AlertMitre.seq == Alert.seq)
                .correlate_except(AlertMitre)
                .exists()
            ),
            log_filter,
        )

        async with self._session() as session:
            tactic_rows = (await session.execute(tactic_stmt)).mappings().all()
            technique_rows = (await session.execute(tech_stmt)).mappings().all()
            untagged = _as_int((await session.execute(untagged_stmt)).scalar())

        tactic_names = {
            entry["tactic_id"]: entry["tactic_name"] for entry in mitre.tactic_catalog()
        }
        tactics = [
            MitreCount(
                id=str(row["id"]),
                name=tactic_names.get(str(row["id"])),
                count=_as_int(row["total"]),
                tactic_id=str(row["id"]),
                tactic_name=tactic_names.get(str(row["id"])),
            )
            for row in tactic_rows
        ]
        techniques = []
        for row in technique_rows:
            technique = mitre.describe(str(row["id"]))
            techniques.append(
                MitreCount(
                    id=str(row["id"]),
                    name=technique.technique_name if technique else None,
                    count=_as_int(row["total"]),
                    tactic_id=str(row["tactic_id"]),
                    tactic_name=tactic_names.get(str(row["tactic_id"])),
                )
            )
        return MitreBreakdown(tactics=tactics, techniques=techniques, untagged=untagged)


    async def overview(self, log_filter: LogFilter) -> OverviewResponse:
        stmt = self._filtered(
            select(
                func.count().label("total"),
                func.min(Alert.ts_epoch).label("first_ts"),
                func.max(Alert.ts_epoch).label("last_ts"),
                func.count(func.distinct(Alert.rule_id)).label("rules"),
                func.count(func.distinct(Alert.src_ip)).label("src_ips"),
                func.count(func.distinct(Alert.user_name)).label("users"),
                func.count(func.distinct(Alert.agent_id)).label("agents"),
                func.sum(case((Alert.rule_mail.is_(True), 1), else_=0)).label("mail"),
                func.sum(
                    case(
                        (
                            (Alert.severity == "critical")
                            & Alert.triage_status.in_(["new", "in_progress"]),
                            1,
                        ),
                        else_=0,
                    )
                ).label("open_critical"),
            ),
            log_filter,
        )
        triage_stmt = self._filtered(
            select(Alert.triage_status, func.count().label("total")).group_by(
                Alert.triage_status
            ),
            log_filter,
        )
        async with self._session() as session:
            row = (await session.execute(stmt)).mappings().one()
            triage_rows = (await session.execute(triage_stmt)).all()
        severity = await self.severity_distribution(log_filter)

        total = _as_int(row["total"])
        first_ts, last_ts = row["first_ts"], row["last_ts"]
        window = float(last_ts) - float(first_ts) if first_ts and last_ts else 0.0
        return OverviewResponse(
            total_events=total,
            first_event=(
                datetime.fromtimestamp(float(first_ts), tz=timezone.utc)
                if first_ts
                else None
            ),
            last_event=(
                datetime.fromtimestamp(float(last_ts), tz=timezone.utc)
                if last_ts
                else None
            ),
            window_seconds=round(window, 2),
            events_per_second=round(total / window, 3) if window > 0 else 0.0,
            severity=severity,
            triage=[
                FieldCount(key=str(status), count=_as_int(count))
                for status, count in triage_rows
            ],
            unique_rules=_as_int(row["rules"]),
            unique_source_ips=_as_int(row["src_ips"]),
            unique_users=_as_int(row["users"]),
            unique_agents=_as_int(row["agents"]),
            mail_flagged=_as_int(row["mail"]),
            open_critical=_as_int(row["open_critical"]),
        )

    async def group_events(
        self,
        log_filter: LogFilter,
        group_by: Sequence[str],
        *,
        min_count: int = 2,
        limit: int = 25,
    ) -> list[CorrelationGroup]:
        columns = [c for c in group_by if c]
        if not columns:
            raise ValueError("group_by_required")
        for column in columns:
            if column not in GROUPABLE_COLUMNS:
                raise ValueError(f"unsupported_group_column:{column}")

        cols = [ALERT_COLUMNS[c] for c in columns]
        stmt = (
            self._filtered(
                select(
                    *[col.label(f"grp_{name}") for name, col in zip(columns, cols)],
                    func.count().label("total"),
                    func.min(Alert.ts_epoch).label("first_ts"),
                    func.max(Alert.ts_epoch).label("last_ts"),
                    func.count(func.distinct(Alert.src_ip)).label("uniq_ips"),
                    func.count(func.distinct(Alert.user_name)).label("uniq_users"),
                    func.max(Alert.rule_level).label("level"),
                    func.max(Alert.rule_description).label("description"),
                    func.min(Alert.seq).label("sample_seq"),
                    func.group_concat(Alert.src_ip.distinct()).label("ips"),
                    func.group_concat(Alert.user_name.distinct()).label("users"),
                )
                .group_by(*cols)
                .having(func.count() >= max(1, min_count)),
                log_filter,
            )
            .order_by(func.count().desc(), func.min(Alert.ts_epoch).asc())
            .limit(max(1, limit))
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).mappings().all()

        groups: list[CorrelationGroup] = []
        for row in rows:
            values = [str(row[f"grp_{c}"] or "-") for c in columns]
            first_ts, last_ts = row["first_ts"], row["last_ts"]
            groups.append(
                CorrelationGroup(
                    signature=" | ".join(values),
                    rule_id=str(row["grp_rule_id"]) if "rule_id" in columns else None,
                    description=row["description"],
                    severity=Severity.from_level(row["level"]),
                    count=_as_int(row["total"]),
                    first_seen=(
                        datetime.fromtimestamp(float(first_ts), tz=timezone.utc)
                        if first_ts
                        else None
                    ),
                    last_seen=(
                        datetime.fromtimestamp(float(last_ts), tz=timezone.utc)
                        if last_ts
                        else None
                    ),
                    duration_seconds=(
                        round(float(last_ts) - float(first_ts), 2)
                        if first_ts and last_ts
                        else 0.0
                    ),
                    unique_src_ips=_as_int(row["uniq_ips"]),
                    unique_users=_as_int(row["uniq_users"]),
                    sample_src_ips=_split_concat(row["ips"]),
                    sample_users=_split_concat(row["users"]),
                    sample_seq=_as_int(row["sample_seq"]) or None,
                )
            )
        return groups

    async def triage_summary(self) -> TriageSummary:
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(Alert.triage_status, func.count()).group_by(Alert.triage_status)
                )
            ).all()
            total = _as_int(
                (await session.execute(select(func.count()).select_from(Alert))).scalar()
            )
            critical = (
                await session.execute(
                    select(func.count(), func.min(Alert.ts_epoch)).where(
                        Alert.severity == "critical",
                        Alert.triage_status.in_(["new", "in_progress"]),
                    )
                )
            ).one()
        open_critical, oldest = critical
        return TriageSummary(
            total=total,
            by_status=[
                FieldCount(key=str(status), count=_as_int(count))
                for status, count in rows
            ],
            open_critical=_as_int(open_critical),
            oldest_open=(
                datetime.fromtimestamp(float(oldest), tz=timezone.utc) if oldest else None
            ),
        )
