"""Aggregation endpoints backing the dashboard charts."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from domain.queries import (
    DashboardResponse,
    FieldCount,
    IpCount,
    MitreBreakdown,
    OverviewResponse,
    RuleCount,
    SeverityDistribution,
    TimelineInterval,
    TimelineResponse,
)
from routers.dependencies import FilterDep, get_analytics_service
from services.analytics import AnalyticsService

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

AnalyticsDep = Annotated[AnalyticsService, Depends(get_analytics_service)]
LimitQuery = Annotated[int, Query(ge=1, le=100, description="Maximum rows.")]


@router.get("/overview", response_model=OverviewResponse, summary="Headline KPIs")
async def overview(service: AnalyticsDep, log_filter: FilterDep) -> OverviewResponse:
    """Totals, cardinalities, severity mix and open-critical count."""
    return await service.overview(log_filter)


@router.get("/timeline", response_model=TimelineResponse, summary="Events over time")
async def timeline(
    service: AnalyticsDep,
    log_filter: FilterDep,
    interval: Annotated[
        TimelineInterval,
        Query(description="Bucket width; 'auto' targets ~60 buckets."),
    ] = TimelineInterval.AUTO,
) -> TimelineResponse:
    """Histogram of events per time bucket, split by severity."""
    return await service.timeline(log_filter, interval)


@router.get(
    "/severity",
    response_model=SeverityDistribution,
    summary="Severity distribution",
)
async def severity(
    service: AnalyticsDep, log_filter: FilterDep
) -> SeverityDistribution:
    """Counts and percentages per severity bucket (pie/doughnut data)."""
    return await service.severity(log_filter)


@router.get("/top-rules", response_model=list[RuleCount], summary="Top rules")
async def top_rules(
    service: AnalyticsDep, log_filter: FilterDep, limit: LimitQuery = 10
) -> list[RuleCount]:
    """Most frequently triggered rules."""
    return await service.top_rules(log_filter, limit)


@router.get("/top-ips", response_model=list[IpCount], summary="Top IP addresses")
async def top_ips(
    service: AnalyticsDep,
    log_filter: FilterDep,
    direction: Annotated[
        str, Query(description="'source', 'destination' or 'agent'.")
    ] = "source",
    limit: LimitQuery = 10,
) -> list[IpCount]:
    """Busiest addresses, with per-address user count and worst severity."""
    try:
        return await service.top_ips(log_filter, direction, limit)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.get(
    "/top-fields/{column}",
    response_model=list[FieldCount],
    summary="Top values of any field",
)
async def top_fields(
    service: AnalyticsDep,
    log_filter: FilterDep,
    column: Annotated[str, Path(description="Field to aggregate.")],
    limit: LimitQuery = 10,
) -> list[FieldCount]:
    """Generic top-N aggregation over an allow-listed column."""
    try:
        return await service.top_field(log_filter, column, limit)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.get("/mitre", response_model=MitreBreakdown, summary="ATT&CK coverage")
async def mitre(
    service: AnalyticsDep, log_filter: FilterDep, limit: LimitQuery = 20
) -> MitreBreakdown:
    """Tactic and technique counts, plus how many alerts carry no mapping."""
    return await service.mitre(log_filter, limit)


@router.get(
    "/dashboard",
    response_model=DashboardResponse,
    summary="Every chart in one request",
)
async def dashboard(
    service: AnalyticsDep,
    log_filter: FilterDep,
    interval: Annotated[TimelineInterval, Query()] = TimelineInterval.AUTO,
    limit: LimitQuery = 10,
) -> DashboardResponse:
    """Single round-trip payload for the whole dashboard."""
    return await service.dashboard(log_filter, interval, limit)
