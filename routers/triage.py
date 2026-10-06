"""Triage endpoints: mark alerts in progress, resolved or false positive."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from domain.models import TriageStatus
from domain.queries import (
    LogPage,
    TriageBulkRequest,
    TriageEvent,
    TriageResult,
    TriageSummary,
    TriageUpdateRequest,
)
from routers.dependencies import FilterDep, PaginationDep, get_triage_service
from services.triage import TriageService

router = APIRouter(prefix="/api/v1/triage", tags=["triage"])

TriageDep = Annotated[TriageService, Depends(get_triage_service)]


@router.get("/summary", response_model=TriageSummary, summary="Queue counters")
async def summary(service: TriageDep) -> TriageSummary:
    """Alert counts per workflow state, plus the oldest untouched critical."""
    return await service.summary()


@router.get("/queue", response_model=LogPage, summary="Alerts in a given state")
async def queue(
    service: TriageDep,
    log_filter: FilterDep,
    pagination: PaginationDep,
    triage: Annotated[
        TriageStatus | None, Query(description="Workflow state to list.")
    ] = TriageStatus.NEW,
) -> LogPage:
    """List the triage queue for one workflow state, newest first."""
    return await service.queue(triage, pagination, log_filter)


@router.post(
    "/bulk",
    response_model=TriageResult,
    summary="Update many alerts at once",
)
async def bulk_update(
    service: TriageDep, request: TriageBulkRequest
) -> TriageResult:
    """Apply one workflow state to up to 1000 alerts.

    Unknown sequence numbers are skipped, so a stale selection in the UI never
    fails the whole action.
    """
    return await service.bulk_update(request)


@router.patch(
    "/{seq}",
    response_model=TriageResult,
    summary="Update one alert",
    responses={404: {"description": "No alert with that sequence number."}},
)
async def update(
    service: TriageDep,
    seq: Annotated[int, Path(ge=1, description="Store sequence number.")],
    request: TriageUpdateRequest,
) -> TriageResult:
    """Set an alert's workflow state and record who did it."""
    result = await service.update(seq, request)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="alert_not_found"
        )
    return result


@router.get(
    "/{seq}/history",
    response_model=list[TriageEvent],
    summary="Triage audit trail",
)
async def history(
    service: TriageDep,
    seq: Annotated[int, Path(ge=1, description="Store sequence number.")],
) -> list[TriageEvent]:
    """Every state change recorded for one alert, oldest first."""
    return await service.history(seq)
