"""Aggregations for the dashboard charts.

Every method takes the same :class:`LogFilter` as the search endpoints, so the
charts always describe exactly the slice the analyst is looking at.
"""

from __future__ import annotations

from core.config import Settings
from domain.queries import (
    DashboardResponse,
    FieldCount,
    IpCount,
    LogFilter,
    MitreBreakdown,
    OverviewResponse,
    RuleCount,
    SeverityDistribution,
    TimelineInterval,
    TimelineResponse,
)
from repositories.base import LogRepository

#: Bucket widths (seconds) the auto-interval picker may choose from.
_AUTO_BUCKETS: tuple[int, ...] = (1, 5, 15, 60, 300, 900, 3_600, 21_600, 86_400)

#: Target number of buckets when the interval is chosen automatically.
_TARGET_BUCKETS = 60


class AnalyticsService:
    """Chart-ready aggregations over the stored alert history."""

    def __init__(self, repository: LogRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings

    async def overview(self, log_filter: LogFilter) -> OverviewResponse:
        """Headline KPI card values."""
        return await self._repository.overview(log_filter)

    async def severity(self, log_filter: LogFilter) -> SeverityDistribution:
        """Severity distribution, ready for a pie/doughnut chart."""
        items = await self._repository.severity_distribution(log_filter)
        return SeverityDistribution(
            total=sum(item.count for item in items), items=items
        )

    async def timeline(
        self,
        log_filter: LogFilter,
        interval: TimelineInterval = TimelineInterval.AUTO,
    ) -> TimelineResponse:
        """Events-over-time histogram.

        With ``interval=auto`` the bucket width is derived from the selected
        time span, targeting roughly 60 buckets so the chart stays readable
        whether the analyst is looking at five minutes or five days.
        """
        seconds = await self._resolve_interval(log_filter, interval)
        points = await self._repository.timeline(log_filter, seconds)
        label = interval.value if interval is not TimelineInterval.AUTO else f"{seconds}s"
        return TimelineResponse(
            interval=label,
            interval_seconds=seconds,
            total=sum(point.count for point in points),
            points=points,
        )

    async def top_rules(
        self, log_filter: LogFilter, limit: int = 10
    ) -> list[RuleCount]:
        """Top triggered rules (default top 10)."""
        return await self._repository.top_rules(log_filter, limit)

    async def top_ips(
        self,
        log_filter: LogFilter,
        direction: str = "source",
        limit: int = 10,
    ) -> list[IpCount]:
        """Top source or destination addresses.

        Args:
            log_filter: Active selection.
            direction: ``source``, ``destination`` or ``agent``.
            limit: Maximum rows to return.

        Raises:
            ValueError: If ``direction`` is not recognised.
        """
        column = {
            "source": "src_ip",
            "src": "src_ip",
            "destination": "dst_ip",
            "dst": "dst_ip",
            "agent": "agent_ip",
        }.get(direction.lower())
        if column is None:
            raise ValueError(f"unsupported_direction:{direction}")
        return await self._repository.top_ips(log_filter, column, limit)

    async def top_field(
        self, log_filter: LogFilter, column: str, limit: int = 10
    ) -> list[FieldCount]:
        """Generic top-N aggregation over an allow-listed column."""
        return await self._repository.top_field(log_filter, column, limit)

    async def mitre(self, log_filter: LogFilter, limit: int = 20) -> MitreBreakdown:
        """ATT&CK tactic/technique coverage for the selection."""
        return await self._repository.mitre_breakdown(log_filter, limit)

    async def dashboard(
        self,
        log_filter: LogFilter,
        interval: TimelineInterval = TimelineInterval.AUTO,
        limit: int = 10,
    ) -> DashboardResponse:
        """Every dashboard aggregation in one response.

        Queries run sequentially on purpose: they share a single SQLite
        connection, so issuing them concurrently would add contention without
        adding parallelism.
        """
        return DashboardResponse(
            overview=await self.overview(log_filter),
            timeline=await self.timeline(log_filter, interval),
            severity=await self.severity(log_filter),
            top_rules=await self.top_rules(log_filter, limit),
            top_source_ips=await self.top_ips(log_filter, "source", limit),
            top_destination_ips=await self.top_ips(log_filter, "destination", limit),
            mitre=await self.mitre(log_filter, limit),
            top_users=await self.top_field(log_filter, "user_name", limit),
            top_services=await self.top_field(log_filter, "service", limit),
        )

    async def _resolve_interval(
        self, log_filter: LogFilter, interval: TimelineInterval
    ) -> int:
        """Pick a bucket width in seconds for the requested interval."""
        if interval is not TimelineInterval.AUTO:
            return interval.seconds

        span: float | None = None
        if log_filter.time_from and log_filter.time_to:
            span = (log_filter.time_to - log_filter.time_from).total_seconds()
        else:
            overview = await self._repository.overview(log_filter)
            if overview.window_seconds:
                span = overview.window_seconds

        if not span or span <= 0:
            return 60

        ideal = span / _TARGET_BUCKETS
        for bucket in _AUTO_BUCKETS:
            if bucket >= ideal:
                return bucket
        return _AUTO_BUCKETS[-1]
