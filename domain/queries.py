"""Query, aggregation and workflow contracts.

``LogFilter`` is the single filter object understood by every read path —
search, analytics, correlation and export — so a chart, a table and a CSV
download always agree on what "the current selection" means.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from domain.models import LogRecord, Severity, TriageStatus

MAX_LIST_FILTER_ITEMS = 50
MAX_SEARCH_LENGTH = 200


class SortOrder(StrEnum):
    """Sort direction for time-ordered result sets."""

    ASC = "asc"
    DESC = "desc"


class TimelineInterval(StrEnum):
    """Bucket width for the events-over-time histogram."""

    AUTO = "auto"
    MINUTE = "1m"
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    HOUR = "1h"
    SIX_HOURS = "6h"
    DAY = "1d"

    @property
    def seconds(self) -> int:
        """Bucket width in seconds (``AUTO`` resolves to one minute)."""
        return {
            "auto": 60,
            "1m": 60,
            "5m": 300,
            "15m": 900,
            "1h": 3600,
            "6h": 21_600,
            "1d": 86_400,
        }[self.value]


class LogFilter(BaseModel):
    """Composable filter applied to every read path.

    Every list field is OR-ed internally and AND-ed across fields, e.g.
    ``severities=[high, critical]`` plus ``src_ips=[1.2.3.4]`` means
    "high or critical alerts *from* 1.2.3.4".
    """

    time_from: datetime | None = None
    time_to: datetime | None = None

    severities: list[Severity] = Field(default_factory=list)
    min_level: int | None = Field(default=None, ge=0, le=15)
    max_level: int | None = Field(default=None, ge=0, le=15)

    rule_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)

    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    log_levels: list[str] = Field(default_factory=list)

    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    triage_statuses: list[TriageStatus] = Field(default_factory=list)
    q: str = Field(default="", max_length=MAX_SEARCH_LENGTH)

    @field_validator("time_from", "time_to")
    @classmethod
    def _to_utc(cls, value: datetime | None) -> datetime | None:
        """Interpret naive datetimes as UTC and normalize aware ones."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator(
        "rule_ids",
        "alert_ids",
        "groups",
        "src_ips",
        "dst_ips",
        "users",
        "services",
        "agents",
        "log_levels",
        "mitre_tactics",
        "mitre_techniques",
    )
    @classmethod
    def _clean_list(cls, values: list[str]) -> list[str]:
        """Drop blanks, deduplicate, preserve order and cap the list length."""
        seen: dict[str, None] = {}
        for item in values:
            cleaned = (item or "").strip()
            if cleaned:
                seen.setdefault(cleaned, None)
        return list(seen)[:MAX_LIST_FILTER_ITEMS]

    @field_validator("log_levels")
    @classmethod
    def _upper_levels(cls, values: list[str]) -> list[str]:
        """Application log levels are upper-case (``INFO``/``WARN``/``ERROR``)."""
        return [v.upper() for v in values]

    @field_validator("mitre_tactics", "mitre_techniques")
    @classmethod
    def _upper_mitre(cls, values: list[str]) -> list[str]:
        """ATT&CK identifiers are upper-case (``TA0006``/``T1110``)."""
        return [v.upper() for v in values]

    @field_validator("q")
    @classmethod
    def _clean_query(cls, value: str) -> str:
        """Trim the free-text query and strip control characters."""
        cleaned = "".join(ch for ch in (value or "") if ch.isprintable())
        return cleaned.strip()

    @model_validator(mode="after")
    def _check_ranges(self) -> "LogFilter":
        """Reject inverted time and level ranges instead of silently emptying."""
        if self.time_from and self.time_to and self.time_from > self.time_to:
            raise ValueError("time_from must not be later than time_to")
        if (
            self.min_level is not None
            and self.max_level is not None
            and self.min_level > self.max_level
        ):
            raise ValueError("min_level must not be greater than max_level")
        return self

    @property
    def is_empty(self) -> bool:
        """True when the filter selects everything."""
        return self == LogFilter()

    def describe(self) -> dict[str, Any]:
        """Human-readable summary of active criteria (used in export metadata)."""
        return {
            key: value
            for key, value in self.model_dump(mode="json", exclude_defaults=True).items()
        }


class Pagination(BaseModel):
    """Offset pagination with a bounded page size."""

    limit: int = Field(default=100, ge=1, le=1_000)
    offset: int = Field(default=0, ge=0)
    order: SortOrder = SortOrder.DESC


# --------------------------------------------------------------------------- #
# Search responses
# --------------------------------------------------------------------------- #
class LogPage(BaseModel):
    """A page of search results."""

    total: int
    limit: int
    offset: int
    returned: int
    took_ms: float
    items: list[LogRecord]


# --------------------------------------------------------------------------- #
# Analytics responses
# --------------------------------------------------------------------------- #
class SeverityCount(BaseModel):
    """One slice of the severity distribution (pie/doughnut chart)."""

    severity: Severity
    count: int
    percentage: float


class SeverityDistribution(BaseModel):
    """Severity breakdown for the current selection."""

    total: int
    items: list[SeverityCount]


class TimelinePoint(BaseModel):
    """One histogram bucket of the events-over-time chart."""

    bucket: datetime
    count: int
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class TimelineResponse(BaseModel):
    """Events over time, bucketed on a fixed interval."""

    interval: str
    interval_seconds: int
    total: int
    points: list[TimelinePoint]


class RuleCount(BaseModel):
    """An aggregated rule row for the "top triggered rules" chart."""

    rule_id: str | None
    description: str | None
    level: int | None
    severity: Severity
    count: int
    groups: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class IpCount(BaseModel):
    """An aggregated IP row for the top source/destination charts."""

    ip: str
    count: int
    unique_users: int = 0
    max_level: int | None = None
    severity: Severity = Severity.LOW
    critical_count: int = 0


class FieldCount(BaseModel):
    """Generic ``key -> count`` aggregation row."""

    key: str
    count: int
    label: str | None = None


class MitreCount(BaseModel):
    """ATT&CK aggregation row."""

    id: str
    name: str | None = None
    count: int
    tactic_id: str | None = None
    tactic_name: str | None = None


class MitreBreakdown(BaseModel):
    """Tactic and technique aggregations for ATT&CK coverage views."""

    tactics: list[MitreCount]
    techniques: list[MitreCount]
    untagged: int = 0


class OverviewResponse(BaseModel):
    """Headline KPIs for the dashboard cards."""

    total_events: int
    first_event: datetime | None = None
    last_event: datetime | None = None
    window_seconds: float = 0.0
    events_per_second: float = 0.0
    severity: list[SeverityCount] = Field(default_factory=list)
    triage: list[FieldCount] = Field(default_factory=list)
    unique_rules: int = 0
    unique_source_ips: int = 0
    unique_users: int = 0
    unique_agents: int = 0
    mail_flagged: int = 0
    open_critical: int = 0


class DashboardResponse(BaseModel):
    """Single round-trip payload backing the whole dashboard."""

    overview: OverviewResponse
    timeline: TimelineResponse
    severity: SeverityDistribution
    top_rules: list[RuleCount]
    top_source_ips: list[IpCount]
    top_destination_ips: list[IpCount]
    mitre: MitreBreakdown
    top_users: list[FieldCount]
    top_services: list[FieldCount]


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #
class CorrelationGroup(BaseModel):
    """Similar events collapsed into one row."""

    signature: str
    rule_id: str | None = None
    description: str | None = None
    severity: Severity = Severity.LOW
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    duration_seconds: float = 0.0
    unique_src_ips: int = 0
    unique_users: int = 0
    sample_src_ips: list[str] = Field(default_factory=list)
    sample_users: list[str] = Field(default_factory=list)
    sample_seq: int | None = None


class BruteForceIncident(BaseModel):
    """A time-windowed authentication-failure burst."""

    src_ip: str | None = None
    user_name: str | None = None
    attempts: int
    window_seconds: float
    first_seen: datetime
    last_seen: datetime
    rule_ids: list[str] = Field(default_factory=list)
    unique_users: int = 0
    max_level: int | None = None
    severity: Severity = Severity.HIGH
    confidence: Literal["low", "medium", "high"] = "medium"
    sample_seqs: list[int] = Field(default_factory=list)


class CorrelationResponse(BaseModel):
    """Grouping and brute-force detection results."""

    groups: list[CorrelationGroup] = Field(default_factory=list)
    brute_force: list[BruteForceIncident] = Field(default_factory=list)
    window_seconds: int = 60
    threshold: int = 5
    scanned: int = 0


# --------------------------------------------------------------------------- #
# Triage
# --------------------------------------------------------------------------- #
class TriageUpdateRequest(BaseModel):
    """Set the workflow state of a single alert."""

    status: TriageStatus
    analyst: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=2_000)


class TriageBulkRequest(TriageUpdateRequest):
    """Apply the same workflow state to many alerts at once."""

    seqs: list[int] = Field(min_length=1, max_length=1_000)


class TriageResult(BaseModel):
    """Outcome of a triage mutation."""

    updated: int
    status: TriageStatus
    records: list[LogRecord] = Field(default_factory=list)


class TriageEvent(BaseModel):
    """One entry of an alert's triage audit trail."""

    id: int
    seq: int
    status: TriageStatus
    previous_status: TriageStatus | None = None
    analyst: str | None = None
    note: str | None = None
    created_at: datetime


class TriageSummary(BaseModel):
    """Queue counters for the triage board."""

    total: int
    by_status: list[FieldCount]
    open_critical: int = 0
    oldest_open: datetime | None = None


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #
class SourceIngestStatus(BaseModel):
    """Per-file checkpoint inside the ingestion pipeline."""

    name: str
    path: str
    format: str = "ndjson"
    file_exists: bool = False
    file_size: int = 0
    inode: int | None = None
    offset: int = 0


class IngestAcceptResult(BaseModel):
    """Result of accepting a batch of alerts via HTTP push or API poll."""

    accepted: int = 0
    skipped: int = 0
    source: str = "api:push"
    queue_depth: int = 0


class ApiSourceStatus(BaseModel):
    """Runtime status of one HTTP/API poller."""

    name: str
    type: str = "generic"
    url: str = ""
    enabled: bool = False
    running: bool = False
    poll_interval: float = 5.0
    fetched: int = 0
    accepted: int = 0
    skipped: int = 0
    errors: int = 0
    last_poll_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    cursor: str | None = None


class ApiIngestStatus(BaseModel):
    """Aggregate status of the real-time API import subsystem."""

    enabled: bool = False
    running: bool = False
    push_enabled: bool = True
    push_auth_required: bool = False
    sources: list[ApiSourceStatus] = Field(default_factory=list)


class IngestionStatus(BaseModel):
    """Health and progress of the tail/parse/store pipeline."""

    running: bool
    log_file: str
    file_exists: bool
    file_size: int = 0
    inode: int | None = None
    offset: int = 0
    ingested: int = 0
    parse_errors: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    batches_written: int = 0
    events_per_second: float = 0.0
    events_last_window: int = 0
    eps_window_seconds: float = 1.0
    stored_events: int = 0
    last_event_at: datetime | None = None
    live_clients: int = 0
    sources: list[SourceIngestStatus] = Field(default_factory=list)
    api: ApiIngestStatus | None = None
