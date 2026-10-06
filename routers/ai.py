"""GigaChat SOC AI endpoints."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from routers.dependencies import FilterDep, PaginationDep, get_query_service
from services.query import LogQueryService
from soc_ai_analyzer import (
    DEFAULT_MODEL,
    FALLBACK_MODEL,
    SOCAnalysisResponse,
    SocAIAuthError,
    SocAIConfigError,
    SocAIError,
    SocAIResponseError,
    SocAITimeoutError,
    analyze_security_events,
)

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])

QueryDep = Annotated[LogQueryService, Depends(get_query_service)]


class AnalyzeRequest(BaseModel):
    """Explicit event batch for GigaChat analysis."""

    events: list[dict[str, Any]] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Alert dicts (LogRecord-shaped or flat Wazuh-like).",
    )
    model: Literal["GigaChat-Pro", "GigaChat-Max"] = DEFAULT_MODEL
    timeout: float = Field(default=90.0, gt=1.0, le=180.0)


def _http_for(exc: SocAIError) -> HTTPException:
    if isinstance(exc, SocAIConfigError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, SocAIAuthError):
        return HTTPException(status_code=401, detail=str(exc))
    if isinstance(exc, SocAITimeoutError):
        return HTTPException(status_code=504, detail=str(exc))
    if isinstance(exc, SocAIResponseError):
        return HTTPException(status_code=502, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.post(
    "/analyze",
    response_model=SOCAnalysisResponse,
    summary="Analyze an explicit alert batch with GigaChat",
)
async def analyze_batch(body: AnalyzeRequest) -> SOCAnalysisResponse:
    """Send caller-supplied events to GigaChat for structured SOC triage."""
    try:
        return await analyze_security_events(
            body.events,
            model=body.model,
            timeout=body.timeout,
            use_max_fallback=body.model != FALLBACK_MODEL,
        )
    except SocAIError as exc:
        raise _http_for(exc) from exc


@router.post(
    "/analyze/selection",
    response_model=SOCAnalysisResponse,
    summary="Analyze the current filter selection with GigaChat",
)
async def analyze_selection(
    service: QueryDep,
    log_filter: FilterDep,
    pagination: PaginationDep,
    model: Annotated[
        Literal["GigaChat-Pro", "GigaChat-Max"],
        Query(description="GigaChat model id."),
    ] = DEFAULT_MODEL,
    timeout: Annotated[float, Query(gt=1.0, le=180.0)] = 90.0,
) -> SOCAnalysisResponse:
    """Pull matching stored alerts and ask GigaChat to assess them."""
    # Prefer interesting alerts for the LLM when the filter is broad.
    page = await service.search(log_filter, pagination)
    if not page.items:
        raise HTTPException(status_code=404, detail="no_alerts_match_filter")

    events = [item.model_dump(mode="json") for item in page.items]
    # Cap + bias toward higher levels so GigaChat sees signal, not only noise.
    events.sort(key=lambda e: int(e.get("rule_level") or 0), reverse=True)
    events = events[:50]
    try:
        return await analyze_security_events(
            events,
            model=model,
            timeout=timeout,
            use_max_fallback=model != FALLBACK_MODEL,
        )
    except SocAIError as exc:
        raise _http_for(exc) from exc
