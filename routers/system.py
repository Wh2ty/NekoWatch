"""Health, pipeline status and metadata endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from core import mitre
from domain.models import ExportFormat, Severity, TriageStatus
from domain.queries import IngestionStatus, TimelineInterval
from repositories.filters import AGGREGATABLE_COLUMNS
from routers.dependencies import ContainerDep

router = APIRouter(tags=["system"])


@router.get("/health", summary="Liveness and pipeline health")
async def health(container: ContainerDep) -> dict[str, Any]:
    """Report service health plus ingestion and generator state.

    Suitable as a container health check: it touches the database (via the
    stored-event count) rather than only confirming the process is up.
    """
    status = await container.ingestion.status()
    return {
        "status": "ok" if status.running else "degraded",
        "service": container.settings.app_name,
        "version": container.settings.app_version,
        "environment": container.settings.environment,
        # No absolute filesystem paths here — /health is unauthenticated and
        # would otherwise leak server layout to anyone who can reach it.
        "database_reachable": True,
        "full_text_search": container.repository.fts_enabled,
        "ingestion": {
            "running": status.running,
            "file_exists": status.file_exists,
            "offset": status.offset,
            "ingested": status.ingested,
            "stored_events": status.stored_events,
            "queue_depth": status.queue_depth,
            "parse_errors": status.parse_errors,
            "events_per_second": status.events_per_second,
        },
        "api_ingest": container.api_ingest.status().model_dump(mode="json"),
        "generator": container.generator.status(),
        "live_clients": container.hub.client_count,
    }


@router.get(
    "/api/v1/ingestion/status",
    response_model=IngestionStatus,
    summary="Ingestion pipeline status",
    tags=["ingestion"],
)
async def ingestion_status(container: ContainerDep) -> IngestionStatus:
    """Tail position, queue depth, parse errors, throughput and API import."""
    status = await container.ingestion.status()
    status.api = container.api_ingest.status()
    return status


@router.get("/api/v1/meta/mitre", summary="ATT&CK catalog")
async def mitre_catalog() -> dict[str, Any]:
    """Tactics and techniques NekoWatch can attach, for filter dropdowns."""
    return {
        "tactics": mitre.tactic_catalog(),
        "techniques": mitre.catalog(),
        "note": (
            "Logener alerts carry no ATT&CK metadata; these mappings are "
            "applied by NekoWatch from rule id, rule groups and device "
            "fingerprint."
        ),
    }


@router.get("/api/v1/meta/fields", summary="Filterable and aggregatable fields")
async def meta_fields() -> dict[str, Any]:
    """Enumerations the UI needs to build filter controls."""
    return {
        "severities": [s.value for s in Severity],
        "triage_statuses": [s.value for s in TriageStatus],
        "export_formats": [f.value for f in ExportFormat],
        "timeline_intervals": [i.value for i in TimelineInterval],
        "aggregatable_columns": sorted(AGGREGATABLE_COLUMNS),
        "rule_level_range": {"min": 0, "max": 15},
    }
