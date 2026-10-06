"""Persistence for user-defined correlation rules."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, select, update

from db.models import CorrelationRule
from db.session import Database
from domain.rules import (
    CorrelationRuleCreate,
    CorrelationRuleOut,
    CorrelationRuleUpdate,
    RuleField,
    RuleGroupBy,
    RuleOperator,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _to_out(row: CorrelationRule) -> CorrelationRuleOut:
    return CorrelationRuleOut(
        id=row.id,
        name=row.name,
        description=row.description,
        enabled=bool(row.enabled),
        field=RuleField(row.field),
        operator=RuleOperator(row.operator),
        value=row.value,
        window_seconds=row.window_seconds,
        threshold=row.threshold,
        group_by=RuleGroupBy(row.group_by),
        severity=row.severity,
        cooldown_seconds=row.cooldown_seconds,
        hit_count=row.hit_count,
        last_fired_at=_parse_dt(row.last_fired_at),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at),
    )


class RulesRepository:
    """CRUD for ``correlation_rules``."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def list_rules(self, *, enabled_only: bool = False) -> list[CorrelationRuleOut]:
        async with self._db.session() as session:
            stmt = select(CorrelationRule).order_by(CorrelationRule.id.desc())
            if enabled_only:
                stmt = stmt.where(CorrelationRule.enabled.is_(True))
            rows = await session.scalars(stmt)
            return [_to_out(row) for row in rows.all()]

    async def get(self, rule_id: int) -> CorrelationRuleOut | None:
        async with self._db.session() as session:
            row = await session.get(CorrelationRule, rule_id)
            return _to_out(row) if row else None

    async def create(self, payload: CorrelationRuleCreate) -> CorrelationRuleOut:
        now = _utcnow()
        async with self._db.session() as session:
            row = CorrelationRule(
                name=payload.name,
                description=payload.description,
                enabled=payload.enabled,
                field=payload.field.value,
                operator=payload.operator.value,
                value=payload.value,
                window_seconds=payload.window_seconds,
                threshold=payload.threshold,
                group_by=payload.group_by.value,
                severity=payload.severity,
                cooldown_seconds=payload.cooldown_seconds,
                hit_count=0,
                last_fired_at=None,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return _to_out(row)

    async def update(
        self, rule_id: int, payload: CorrelationRuleUpdate
    ) -> CorrelationRuleOut | None:
        data = payload.model_dump(exclude_unset=True)
        if not data:
            return await self.get(rule_id)
        for key in ("field", "operator", "group_by"):
            if key in data and data[key] is not None:
                data[key] = data[key].value if hasattr(data[key], "value") else data[key]
        data["updated_at"] = _utcnow()
        async with self._db.session() as session:
            result = await session.execute(
                update(CorrelationRule)
                .where(CorrelationRule.id == rule_id)
                .values(**data)
            )
            if result.rowcount == 0:
                return None
            await session.commit()
            row = await session.get(CorrelationRule, rule_id)
            return _to_out(row) if row else None

    async def set_enabled(self, rule_id: int, enabled: bool) -> CorrelationRuleOut | None:
        return await self.update(rule_id, CorrelationRuleUpdate(enabled=enabled))

    async def delete(self, rule_id: int) -> bool:
        async with self._db.session() as session:
            result = await session.execute(
                delete(CorrelationRule).where(CorrelationRule.id == rule_id)
            )
            await session.commit()
            return bool(result.rowcount)

    async def mark_fired(self, rule_id: int) -> None:
        now = _utcnow()
        async with self._db.session() as session:
            row = await session.get(CorrelationRule, rule_id)
            if row is None:
                return
            row.hit_count = int(row.hit_count or 0) + 1
            row.last_fired_at = now
            row.updated_at = now
            await session.commit()

    async def seed_defaults_if_empty(self) -> list[CorrelationRuleOut]:
        """Insert a few demo rules when the table is empty (UI / first run)."""
        existing = await self.list_rules()
        if existing:
            return existing
        samples = [
            CorrelationRuleCreate(
                name="Много неудачных входов с одного IP",
                description="Порог по src_ip для типичных auth-failure rule id.",
                enabled=True,
                field=RuleField.RULE_ID,
                operator=RuleOperator.IN,
                value="5712,5752,5503",
                window_seconds=60,
                threshold=5,
                group_by=RuleGroupBy.SRC_IP,
                severity="high",
                cooldown_seconds=120,
            ),
            CorrelationRuleCreate(
                name="Критические события агента",
                description="Любая critical severity в окне 5 минут.",
                enabled=True,
                field=RuleField.SEVERITY,
                operator=RuleOperator.EQ,
                value="critical",
                window_seconds=300,
                threshold=3,
                group_by=RuleGroupBy.AGENT_ID,
                severity="critical",
                cooldown_seconds=180,
            ),
            CorrelationRuleCreate(
                name="Подозрительный пользователь root",
                description="Активность пользователя root (демо-правило, выключено).",
                enabled=False,
                field=RuleField.USER_NAME,
                operator=RuleOperator.EQ,
                value="root",
                window_seconds=120,
                threshold=10,
                group_by=RuleGroupBy.SRC_IP,
                severity="medium",
                cooldown_seconds=60,
            ),
        ]
        created: list[CorrelationRuleOut] = []
        for sample in samples:
            created.append(await self.create(sample))
        return created
