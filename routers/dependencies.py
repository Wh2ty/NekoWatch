"""FastAPI dependencies: container access, filter parsing, pagination.

The filter dependency is the single place query strings become a
:class:`LogFilter`, so ``/logs``, ``/analytics/*``, ``/correlation/*`` and
``/export`` all accept exactly the same parameters and the dashboard can reuse
one query string everywhere.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request, WebSocket, status
from pydantic import ValidationError

from core.container import ServiceContainer
from domain.models import Severity, TriageStatus
from domain.queries import (
    MAX_SEARCH_LENGTH,
    LogFilter,
    Pagination,
    SortOrder,
)
from services.analytics import AnalyticsService
from services.correlation import CorrelationService
from services.export import ExportService
from services.query import LogQueryService
from services.triage import TriageService


def get_container(request: Request) -> ServiceContainer:
    """Fetch the container from application state.

    Raises:
        HTTPException: 503 while the application is still starting up.
    """
    container = getattr(request.app.state, "container", None)
    if container is None:  # pragma: no cover - only during startup races
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="application_starting",
        )
    return container


def get_ws_container(websocket: WebSocket) -> ServiceContainer | None:
    """Container accessor for WebSocket routes (no HTTP error to raise)."""
    return getattr(websocket.app.state, "container", None)


def get_query_service(
    container: Annotated[ServiceContainer, Depends(get_container)],
) -> LogQueryService:
    """Search service."""
    return container.query


def get_analytics_service(
    container: Annotated[ServiceContainer, Depends(get_container)],
) -> AnalyticsService:
    """Analytics service."""
    return container.analytics


def get_correlation_service(
    container: Annotated[ServiceContainer, Depends(get_container)],
) -> CorrelationService:
    """Correlation service."""
    return container.correlation


def get_triage_service(
    container: Annotated[ServiceContainer, Depends(get_container)],
) -> TriageService:
    """Triage service."""
    return container.triage


def get_export_service(
    container: Annotated[ServiceContainer, Depends(get_container)],
) -> ExportService:
    """Export service."""
    return container.export


def log_filter_params(
    time_from: Annotated[
        datetime | None,
        Query(alias="from", description="Start of the time range (ISO-8601, UTC)."),
    ] = None,
    time_to: Annotated[
        datetime | None,
        Query(alias="to", description="End of the time range (ISO-8601, UTC)."),
    ] = None,
    severity: Annotated[
        list[Severity], Query(description="Severity buckets to include.")
    ] = [],
    min_level: Annotated[
        int | None, Query(ge=0, le=15, description="Minimum Wazuh rule level.")
    ] = None,
    max_level: Annotated[
        int | None, Query(ge=0, le=15, description="Maximum Wazuh rule level.")
    ] = None,
    rule_id: Annotated[list[str], Query(description="Wazuh rule ids.")] = [],
    event_id: Annotated[
        list[str], Query(description="Alert (event) ids as emitted by Wazuh.")
    ] = [],
    group: Annotated[list[str], Query(description="Wazuh rule groups.")] = [],
    src_ip: Annotated[list[str], Query(description="Source IP addresses.")] = [],
    dst_ip: Annotated[list[str], Query(description="Destination IP addresses.")] = [],
    user: Annotated[list[str], Query(description="Usernames.")] = [],
    service: Annotated[list[str], Query(description="Service names.")] = [],
    agent: Annotated[list[str], Query(description="Agent id or name.")] = [],
    log_level: Annotated[
        list[str], Query(description="Application log level (INFO/WARN/ERROR).")
    ] = [],
    mitre_tactic: Annotated[
        list[str], Query(description="ATT&CK tactic ids, e.g. TA0006.")
    ] = [],
    mitre_technique: Annotated[
        list[str],
        Query(
            description="ATT&CK technique ids, e.g. T1110. "
            "A parent id also matches its sub-techniques."
        ),
    ] = [],
    triage_status: Annotated[
        list[TriageStatus], Query(description="Triage workflow states.")
    ] = [],
    q: Annotated[
        str,
        Query(
            max_length=MAX_SEARCH_LENGTH,
            description="Full-text search across message, rule and raw payload.",
        ),
    ] = "",
) -> LogFilter:
    """Assemble a :class:`LogFilter` from query parameters.

    Raises:
        HTTPException: 422 when the criteria are contradictory, e.g. an
            inverted time or level range.
    """
    try:
        return LogFilter(
            time_from=time_from,
            time_to=time_to,
            severities=severity,
            min_level=min_level,
            max_level=max_level,
            rule_ids=rule_id,
            alert_ids=event_id,
            groups=group,
            src_ips=src_ip,
            dst_ips=dst_ip,
            users=user,
            services=service,
            agents=agent,
            log_levels=log_level,
            mitre_tactics=mitre_tactic,
            mitre_techniques=mitre_technique,
            triage_statuses=triage_status,
            q=q,
        )
    except ValidationError as exc:
        # include_context=False keeps raw exception objects (from model
        # validators) out of the response body, which json.dumps cannot encode.
        raise HTTPException(
            status_code=422,
            detail=exc.errors(
                include_url=False, include_context=False, include_input=False
            ),
        ) from exc


def pagination_params(
    limit: Annotated[int, Query(ge=1, le=1_000, description="Page size.")] = 100,
    offset: Annotated[int, Query(ge=0, description="Rows to skip.")] = 0,
    order: Annotated[
        SortOrder, Query(description="Sort by event time.")
    ] = SortOrder.DESC,
) -> Pagination:
    """Assemble pagination parameters."""
    return Pagination(limit=limit, offset=offset, order=order)


FilterDep = Annotated[LogFilter, Depends(log_filter_params)]
PaginationDep = Annotated[Pagination, Depends(pagination_params)]
ContainerDep = Annotated[ServiceContainer, Depends(get_container)]
