"""Correlation endpoints: event grouping and brute-force detection."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from domain.queries import BruteForceIncident, CorrelationGroup, CorrelationResponse
from routers.dependencies import FilterDep, get_correlation_service
from services.correlation import CorrelationService

router = APIRouter(prefix="/api/v1/correlation", tags=["correlation"])

CorrelationDep = Annotated[CorrelationService, Depends(get_correlation_service)]


@router.get(
    "/groups",
    response_model=list[CorrelationGroup],
    summary="Group similar events",
)
async def groups(
    service: CorrelationDep,
    log_filter: FilterDep,
    group_by: Annotated[
        list[str],
        Query(description="Signature columns, e.g. rule_id and src_ip."),
    ] = ["rule_id", "src_ip"],
    min_count: Annotated[int, Query(ge=1, le=1_000)] = 2,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> list[CorrelationGroup]:
    """Collapse repeated events into one row per signature.

    Turns thousands of near-identical alerts into a handful of reviewable rows
    with first/last seen, duration and distinct source/user counts.
    """
    try:
        return await service.group(
            log_filter, group_by, min_count=min_count, limit=limit
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.get(
    "/brute-force",
    response_model=list[BruteForceIncident],
    summary="Detect brute-force bursts",
)
async def brute_force(
    service: CorrelationDep,
    log_filter: FilterDep,
    window_seconds: Annotated[int, Query(ge=1, le=86_400)] = 60,
    threshold: Annotated[int, Query(ge=2, le=10_000)] = 5,
    by_user: Annotated[
        bool, Query(description="Key incidents by (src_ip, user) instead of src_ip.")
    ] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[BruteForceIncident]:
    """Find sources with too many authentication failures in a time window."""
    incidents, _ = await service.detect_brute_force(
        log_filter,
        window_seconds=window_seconds,
        threshold=threshold,
        by_user=by_user,
        limit=limit,
    )
    return incidents


@router.get(
    "",
    response_model=CorrelationResponse,
    summary="Grouping and brute-force detection together",
)
async def analyze(
    service: CorrelationDep,
    log_filter: FilterDep,
    window_seconds: Annotated[int, Query(ge=1, le=86_400)] = 60,
    threshold: Annotated[int, Query(ge=2, le=10_000)] = 5,
    min_count: Annotated[int, Query(ge=1, le=1_000)] = 2,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> CorrelationResponse:
    """Run both correlation passes in one request (dashboard convenience)."""
    return await service.analyze(
        log_filter,
        min_count=min_count,
        window_seconds=window_seconds,
        threshold=threshold,
        limit=limit,
    )
