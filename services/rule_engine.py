"""Streaming correlation engine for user-defined rules.

Evaluates each ingested :class:`~domain.models.LogRecord` against active rules,
maintains per-rule sliding windows (optionally grouped), and emits analyst
notifications when a threshold is crossed — with cooldown to avoid storms.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from domain.models import LogRecord
from domain.rules import (
    RULE_FIELD_LABELS,
    RULE_GROUP_BY_LABELS,
    RULE_OPERATOR_LABELS,
    CorrelationRuleCreate,
    CorrelationRuleListResponse,
    CorrelationRuleOut,
    CorrelationRuleUpdate,
    RuleField,
    RuleGroupBy,
    RuleHitOut,
    RuleOperator,
)
from repositories.rules_repo import RulesRepository
from repositories.status_repo import StatusRepository

if TYPE_CHECKING:
    from services.live import LiveHub

logger = logging.getLogger("nekowatch.rules")


def _field_value(record: LogRecord, field_name: RuleField) -> str | None:
    raw = getattr(record, field_name.value, None)
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        return ",".join(str(x) for x in raw)
    return str(raw)


def condition_matches(record: LogRecord, rule: CorrelationRuleOut) -> bool:
    """Return True when ``record`` satisfies the rule's field/operator/value."""
    actual = _field_value(record, rule.field)
    expected = rule.value
    op = rule.operator

    if op is RuleOperator.EQ:
        return actual is not None and actual.lower() == expected.lower()
    if op is RuleOperator.NE:
        return actual is None or actual.lower() != expected.lower()
    if op is RuleOperator.CONTAINS:
        return actual is not None and expected.lower() in actual.lower()
    if op is RuleOperator.STARTS_WITH:
        return actual is not None and actual.lower().startswith(expected.lower())
    if op is RuleOperator.ENDS_WITH:
        return actual is not None and actual.lower().endswith(expected.lower())
    if op is RuleOperator.IN:
        options = {part.strip().lower() for part in expected.split(",") if part.strip()}
        return actual is not None and actual.lower() in options
    if op is RuleOperator.REGEX:
        if actual is None:
            return False
        try:
            return re.search(expected, actual, flags=re.IGNORECASE) is not None
        except re.error:
            logger.warning("invalid_rule_regex", extra={"rule_id": rule.id})
            return False
    if op is RuleOperator.GTE:
        try:
            return actual is not None and float(actual) >= float(expected)
        except ValueError:
            return False
    if op is RuleOperator.LTE:
        try:
            return actual is not None and float(actual) <= float(expected)
        except ValueError:
            return False
    return False


def _group_key(record: LogRecord, group_by: RuleGroupBy) -> str:
    if group_by is RuleGroupBy.NONE:
        return "*"
    value = getattr(record, group_by.value, None)
    return str(value) if value not in (None, "") else "_"


@dataclass
class _WindowBucket:
    """Timestamps + sample seqs for one (rule, group) key."""

    times: deque[float] = field(default_factory=deque)
    seqs: deque[int] = field(default_factory=deque)


class RuleEngine:
    """Loads rules, evaluates ingest batches, writes notifications on hits."""

    def __init__(
        self,
        rules_repo: RulesRepository,
        status_repo: StatusRepository,
        hub: LiveHub | None = None,
    ) -> None:
        self._rules = rules_repo
        self._status = status_repo
        self._hub = hub
        self._cache: list[CorrelationRuleOut] = []
        self._windows: dict[tuple[int, str], _WindowBucket] = defaultdict(_WindowBucket)
        self._last_fire: dict[tuple[int, str], float] = {}
        self._recent_hits: deque[RuleHitOut] = deque(maxlen=50)

    async def start(self) -> None:
        """Seed demo rules if needed and warm the in-memory cache."""
        await self._rules.seed_defaults_if_empty()
        await self.reload()
        logger.info("rule_engine_started", extra={"rules": len(self._cache)})

    async def stop(self) -> None:
        self._cache.clear()
        self._windows.clear()
        self._last_fire.clear()

    async def reload(self) -> None:
        """Refresh the active-rule cache from SQLite."""
        self._cache = await self._rules.list_rules(enabled_only=True)
        active_ids = {rule.id for rule in self._cache}
        stale = [key for key in self._windows if key[0] not in active_ids]
        for key in stale:
            self._windows.pop(key, None)
            self._last_fire.pop(key, None)

    # ---------------------------------------------------------------- catalogue
    @staticmethod
    def catalogue() -> dict[str, list[dict[str, str]]]:
        """Dropdown options for the rule constructor UI."""
        return {
            "fields": [
                {"value": key, "label": label}
                for key, label in RULE_FIELD_LABELS.items()
            ],
            "operators": [
                {"value": key, "label": label}
                for key, label in RULE_OPERATOR_LABELS.items()
            ],
            "group_by": [
                {"value": key, "label": label}
                for key, label in RULE_GROUP_BY_LABELS.items()
            ],
            "severities": [
                {"value": "low", "label": "Низкая"},
                {"value": "medium", "label": "Средняя"},
                {"value": "high", "label": "Высокая"},
                {"value": "critical", "label": "Критическая"},
            ],
        }

    # --------------------------------------------------------------------- CRUD
    async def list_rules(self) -> CorrelationRuleListResponse:
        items = await self._rules.list_rules()
        return CorrelationRuleListResponse(
            items=items, total=len(items), catalogue=self.catalogue()
        )

    async def get_rule(self, rule_id: int) -> CorrelationRuleOut | None:
        return await self._rules.get(rule_id)

    async def create_rule(self, payload: CorrelationRuleCreate) -> CorrelationRuleOut:
        created = await self._rules.create(payload)
        await self.reload()
        return created

    async def update_rule(
        self, rule_id: int, payload: CorrelationRuleUpdate
    ) -> CorrelationRuleOut | None:
        updated = await self._rules.update(rule_id, payload)
        await self.reload()
        return updated

    async def set_enabled(
        self, rule_id: int, enabled: bool
    ) -> CorrelationRuleOut | None:
        updated = await self._rules.set_enabled(rule_id, enabled)
        await self.reload()
        return updated

    async def delete_rule(self, rule_id: int) -> bool:
        deleted = await self._rules.delete(rule_id)
        await self.reload()
        return deleted

    def recent_hits(self) -> list[RuleHitOut]:
        return list(self._recent_hits)

    # --------------------------------------------------------------- evaluation
    async def evaluate_records(self, records: list[LogRecord]) -> list[RuleHitOut]:
        """Apply active rules to a freshly stored batch. Never raises to callers."""
        if not records or not self._cache:
            return []
        hits: list[RuleHitOut] = []
        now = time.monotonic()
        wall = datetime.now(timezone.utc)
        try:
            for record in records:
                event_ts = (
                    record.timestamp.timestamp()
                    if record.timestamp.tzinfo
                    else record.timestamp.replace(tzinfo=timezone.utc).timestamp()
                )
                # Prefer wall clock for windowing relative to "now".
                event_mono = now - max(0.0, wall.timestamp() - event_ts)
                for rule in self._cache:
                    if not condition_matches(record, rule):
                        continue
                    key = (rule.id, _group_key(record, rule.group_by))
                    bucket = self._windows[key]
                    bucket.times.append(event_mono)
                    bucket.seqs.append(int(record.seq or 0))
                    cutoff = now - float(rule.window_seconds)
                    while bucket.times and bucket.times[0] < cutoff:
                        bucket.times.popleft()
                        bucket.seqs.popleft()
                    if len(bucket.times) < rule.threshold:
                        continue
                    last = self._last_fire.get(key, 0.0)
                    if now - last < float(rule.cooldown_seconds):
                        continue
                    hit = await self._fire(rule, key[1], bucket, wall)
                    self._last_fire[key] = now
                    hits.append(hit)
        except Exception:  # noqa: BLE001 - never block ingest
            logger.exception("rule_engine_evaluate_failed")
        return hits

    async def _fire(
        self,
        rule: CorrelationRuleOut,
        group_key: str,
        bucket: _WindowBucket,
        wall: datetime,
    ) -> RuleHitOut:
        match_count = len(bucket.times)
        sample = list(bucket.seqs)[-10:]
        title = f"Правило «{rule.name}»"
        group_part = (
            f", группа {group_key}"
            if rule.group_by is not RuleGroupBy.NONE and group_key not in {"*", "_"}
            else ""
        )
        message = (
            f"{match_count} совпадений за {rule.window_seconds}с"
            f"{group_part} "
            f"({rule.field.value} {rule.operator.value} «{rule.value}», "
            f"порог {rule.threshold}). "
            f"Примеры seq: {', '.join(str(s) for s in sample if s) or '—'}"
        )
        await self._status.create_notification(
            kind="correlation_rule",
            severity=rule.severity,
            title=title,
            message=message,
            source_id=None,
        )
        await self._rules.mark_fired(rule.id)
        hit = RuleHitOut(
            rule_id=rule.id,
            rule_name=rule.name,
            group_key=group_key,
            match_count=match_count,
            severity=rule.severity,
            title=title,
            message=message,
            sample_seqs=[s for s in sample if s],
            fired_at=wall,
        )
        self._recent_hits.appendleft(hit)
        logger.info(
            "correlation_rule_fired",
            extra={
                "rule_id": rule.id,
                "rule_name": rule.name,
                "group_key": group_key,
                "match_count": match_count,
            },
        )
        return hit
