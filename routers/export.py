"""Streaming export endpoint (CSV / JSON / NDJSON)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from domain.models import ExportFormat
from routers.dependencies import FilterDep, get_export_service
from services.export import ExportService

router = APIRouter(prefix="/api/v1/export", tags=["export"])

ExportDep = Annotated[ExportService, Depends(get_export_service)]


@router.get(
    "",
    summary="Export the filtered selection",
    response_description="A streamed file download.",
    responses={
        200: {
            "content": {
                "text/csv": {},
                "application/json": {},
                "application/x-ndjson": {},
            }
        }
    },
)
async def export_logs(
    service: ExportDep,
    log_filter: FilterDep,
    export_format: Annotated[
        ExportFormat, Query(alias="format", description="Output encoding.")
    ] = ExportFormat.CSV,
    ecs: Annotated[
        bool,
        Query(
            description="Emit Elastic Common Schema documents "
            "(JSON/NDJSON only; CSV is always flat)."
        ),
    ] = False,
    ascending: Annotated[
        bool, Query(description="Chronological order when true.")
    ] = True,
) -> StreamingResponse:
    """Download every alert matching the current filter.

    The body is generated while it is sent — the database is read in keyset
    chunks and serialised incrementally — so large exports neither buffer in
    memory nor block the event loop.
    """
    filename = service.filename(export_format)
    return StreamingResponse(
        service.stream(log_filter, export_format, ecs=ecs, ascending=ascending),
        media_type=service.media_type(export_format),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
