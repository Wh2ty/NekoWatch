"""Log search endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from domain.models import LogRecordDetail
from domain.queries import FieldCount, LogPage
from routers.dependencies import (
    FilterDep,
    PaginationDep,
    get_query_service,
)
from services.query import LogQueryService

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

QueryDep = Annotated[LogQueryService, Depends(get_query_service)]


@router.get(
    "",
    response_model=LogPage,
    summary="Search alerts",
    response_description="A page of matching alerts plus the total match count.",
)
async def search_logs(
    service: QueryDep,
    log_filter: FilterDep,
    pagination: PaginationDep,
) -> LogPage:
    """Search stored alerts.

    Combines time range, severity, rule level, rule/event id, source and
    destination IP, user, service, agent, ATT&CK tactic/technique, triage state
    and full-text search. Criteria are AND-ed; repeated values of one parameter
    are OR-ed.
    """
    return await service.search(log_filter, pagination)


@router.get(
    "/fields/{column}",
    response_model=list[FieldCount],
    summary="Distinct values of a field",
)
async def field_values(
    service: QueryDep,
    log_filter: FilterDep,
    column: Annotated[
        str, Path(description="Field to enumerate, e.g. service or user_name.")
    ],
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> list[FieldCount]:
    """List a field's most frequent values — used to populate filter dropdowns."""
    try:
        return await service.field_values(column, limit, log_filter)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.get(
    "/{seq}",
    response_model=LogRecordDetail,
    summary="Alert detail",
    responses={404: {"description": "No alert with that sequence number."}},
)
async def get_log(
    service: QueryDep,
    seq: Annotated[int, Path(ge=1, description="Store sequence number.")],
) -> LogRecordDetail:
    """Fetch one alert with its ECS projection and the original raw payload."""
    detail = await service.get_detail(seq)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="alert_not_found"
        )
    return detail
