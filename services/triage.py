"""Analyst triage workflow.

Every state change is written to an append-only audit table, so "who closed
this alert and why" survives later edits — the minimum an auditor expects from
a SOC tool.
"""

from __future__ import annotations

import logging

from core.config import Settings
from domain.models import TriageStatus
from domain.queries import (
    LogFilter,
    LogPage,
    Pagination,
    TriageBulkRequest,
    TriageEvent,
    TriageResult,
    TriageSummary,
    TriageUpdateRequest,
)
from repositories.base import LogRepository

logger = logging.getLogger("nekowatch.triage")


class TriageService:
    """Marks alerts as in progress, resolved or false positive."""

    def __init__(self, repository: LogRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings

    async def update(
        self, seq: int, request: TriageUpdateRequest
    ) -> TriageResult | None:
        """Set the workflow state of one alert.

        Returns:
            The result with the refreshed record, or ``None`` when the alert
            does not exist so the router can answer 404.
        """
        updated = await self._repository.set_triage(
            [seq], request.status, request.analyst, request.note
        )
        if not updated:
            return None

        found = await self._repository.get(seq)
        records = [found[0]] if found else []
        logger.info(
            "triage_updated",
            extra={
                "seq": seq,
                "status": request.status.value,
                "analyst": request.analyst,
            },
        )
        return TriageResult(updated=updated, status=request.status, records=records)

    async def bulk_update(self, request: TriageBulkRequest) -> TriageResult:
        """Apply one state to many alerts.

        Unknown sequence numbers are ignored rather than failing the batch, so
        a stale UI selection cannot block the whole action.
        """
        updated = await self._repository.set_triage(
            request.seqs, request.status, request.analyst, request.note
        )
        logger.info(
            "triage_bulk_updated",
            extra={
                "requested": len(request.seqs),
                "updated": updated,
                "status": request.status.value,
            },
        )
        return TriageResult(updated=updated, status=request.status, records=[])

    async def summary(self) -> TriageSummary:
        """Queue counters for the triage board."""
        return await self._repository.triage_summary()

    async def history(self, seq: int) -> list[TriageEvent]:
        """Audit trail of one alert, oldest first."""
        return await self._repository.triage_history(seq)

    async def queue(
        self,
        status: TriageStatus | None = None,
        pagination: Pagination | None = None,
        base_filter: LogFilter | None = None,
    ) -> LogPage:
        """List alerts in a given workflow state, newest first."""
        page = pagination or Pagination()
        log_filter = (base_filter or LogFilter()).model_copy(
            update={"triage_statuses": [status] if status else []}
        )
        total = await self._repository.count(log_filter)
        items = await self._repository.search(log_filter, page)
        return LogPage(
            total=total,
            limit=page.limit,
            offset=page.offset,
            returned=len(items),
            took_ms=0.0,
            items=items,
        )
