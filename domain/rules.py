"""Custom correlation rules: schema, CRUD DTOs and field catalogue."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class RuleOperator(StrEnum):
    """Comparison applied to a log field value."""

    EQ = "eq"
    NE = "ne"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    IN = "in"
    GTE = "gte"
    LTE = "lte"


class RuleField(StrEnum):
    """Allow-listed :class:`~domain.models.LogRecord` attributes."""

    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    USER_NAME = "user_name"
    RULE_ID = "rule_id"
    RULE_LEVEL = "rule_level"
    SEVERITY = "severity"
    MESSAGE = "message"
    RULE_DESCRIPTION = "rule_description"
    AGENT_NAME = "agent_name"
    AGENT_ID = "agent_id"
    SERVICE = "service"
    LOG_LEVEL = "log_level"
    HOSTNAME = "hostname"


class RuleGroupBy(StrEnum):
    """Optional grouping key for threshold windows."""

    NONE = "none"
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    USER_NAME = "user_name"
    AGENT_ID = "agent_id"
    RULE_ID = "rule_id"
    SERVICE = "service"


#: Human-readable labels for the rule constructor UI.
RULE_FIELD_LABELS: dict[str, str] = {
    RuleField.SRC_IP: "IP источника",
    RuleField.DST_IP: "IP назначения",
    RuleField.USER_NAME: "Пользователь",
    RuleField.RULE_ID: "ID правила",
    RuleField.RULE_LEVEL: "Уровень правила",
    RuleField.SEVERITY: "Критичность",
    RuleField.MESSAGE: "Сообщение",
    RuleField.RULE_DESCRIPTION: "Описание правила",
    RuleField.AGENT_NAME: "Имя агента",
    RuleField.AGENT_ID: "ID агента",
    RuleField.SERVICE: "Сервис",
    RuleField.LOG_LEVEL: "Уровень лога",
    RuleField.HOSTNAME: "Хост",
}

RULE_OPERATOR_LABELS: dict[str, str] = {
    RuleOperator.EQ: "равно",
    RuleOperator.NE: "не равно",
    RuleOperator.CONTAINS: "содержит",
    RuleOperator.STARTS_WITH: "начинается с",
    RuleOperator.ENDS_WITH: "заканчивается на",
    RuleOperator.REGEX: "regex",
    RuleOperator.IN: "в списке (через запятую)",
    RuleOperator.GTE: "≥",
    RuleOperator.LTE: "≤",
}

RULE_GROUP_BY_LABELS: dict[str, str] = {
    RuleGroupBy.NONE: "Без группировки",
    RuleGroupBy.SRC_IP: "По IP источника",
    RuleGroupBy.DST_IP: "По IP назначения",
    RuleGroupBy.USER_NAME: "По пользователю",
    RuleGroupBy.AGENT_ID: "По агенту",
    RuleGroupBy.RULE_ID: "По ID правила",
    RuleGroupBy.SERVICE: "По сервису",
}


class CorrelationRuleBase(BaseModel):
    """Shared fields for create/update."""

    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    enabled: bool = True
    field: RuleField
    operator: RuleOperator
    value: str = Field(..., min_length=1, max_length=512)
    window_seconds: int = Field(default=60, ge=5, le=3600)
    threshold: int = Field(default=5, ge=1, le=10_000)
    group_by: RuleGroupBy = RuleGroupBy.NONE
    severity: str = Field(default="high", max_length=16)
    cooldown_seconds: int = Field(
        default=60,
        ge=0,
        le=3600,
        description="Minimum seconds between notifications for the same rule+group.",
    )

    @field_validator("severity")
    @classmethod
    def _severity_ok(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        cleaned = value.strip().lower()
        if cleaned not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return cleaned

    @field_validator("name", "value")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class CorrelationRuleCreate(CorrelationRuleBase):
    """Body for ``POST /rules``."""


class CorrelationRuleUpdate(BaseModel):
    """Partial update for ``PATCH /rules/{id}``."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    field: RuleField | None = None
    operator: RuleOperator | None = None
    value: str | None = Field(default=None, min_length=1, max_length=512)
    window_seconds: int | None = Field(default=None, ge=5, le=3600)
    threshold: int | None = Field(default=None, ge=1, le=10_000)
    group_by: RuleGroupBy | None = None
    severity: str | None = Field(default=None, max_length=16)
    cooldown_seconds: int | None = Field(default=None, ge=0, le=3600)

    @field_validator("severity")
    @classmethod
    def _severity_ok(cls, value: str | None) -> str | None:
        if value is None:
            return value
        allowed = {"low", "medium", "high", "critical"}
        cleaned = value.strip().lower()
        if cleaned not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return cleaned


class CorrelationRuleOut(CorrelationRuleBase):
    """API representation of a stored rule."""

    id: int
    hit_count: int = 0
    last_fired_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CorrelationRuleListResponse(BaseModel):
    """List payload for the rules manager UI."""

    items: list[CorrelationRuleOut]
    total: int
    catalogue: dict[str, list[dict[str, str]]]


class RuleHitOut(BaseModel):
    """One firing of a custom rule (for UI / tests)."""

    rule_id: int
    rule_name: str
    group_key: str
    match_count: int
    severity: str
    title: str
    message: str
    sample_seqs: list[int] = Field(default_factory=list)
    fired_at: datetime
