"""Search and drill-down over stored alerts."""

from __future__ import annotations

import json
import time
from typing import Any

from core.config import Settings
from domain.models import LogRecordDetail
from domain.queries import FieldCount, LogFilter, LogPage, Pagination
from repositories.base import LogRepository
from repositories.filters import AGGREGATABLE_COLUMNS


class LogQueryService:
    """Filtered search, pagination and single-event drill-down."""

    def __init__(self, repository: LogRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings

    async def search(
        self, log_filter: LogFilter, pagination: Pagination
    ) -> LogPage:
        """Run a filtered search and return one page with the total match count.

        The total is computed with a separate ``COUNT(*)`` so the UI can render
        pagination and "N matches" without materialising the whole result set.
        """
        started = time.perf_counter()
        capped = Pagination(
            limit=min(pagination.limit, self._settings.max_page_size),
            offset=pagination.offset,
            order=pagination.order,
        )
        total = await self._repository.count(log_filter)
        items = await self._repository.search(log_filter, capped)
        return LogPage(
            total=total,
            limit=capped.limit,
            offset=capped.offset,
            returned=len(items),
            took_ms=round((time.perf_counter() - started) * 1000, 2),
            items=items,
        )

    async def get_detail(self, seq: int) -> LogRecordDetail | None:
        """Fetch one alert with its ECS projection and original payload.

        Returns:
            ``None`` when no alert with that sequence number exists.
        """
        found = await self._repository.get(seq)
        if found is None:
            return None
        record, raw = found
        return LogRecordDetail(
            record=record,
            ecs=record.to_ecs(),
            raw=raw,
            payload=_safe_json(raw),
        )

    async def field_values(
        self, column: str, limit: int = 25, log_filter: LogFilter | None = None
    ) -> list[FieldCount]:
        """Distinct values of a field, most frequent first.

        Powers the dashboard's filter dropdowns (agents, services, users, ...).

        Raises:
            ValueError: If ``column`` is not aggregatable.
        """
        if column not in AGGREGATABLE_COLUMNS:
            raise ValueError(f"unsupported_column:{column}")
        return await self._repository.top_field(
            log_filter or LogFilter(), column, limit
        )


def _safe_json(raw: str | None) -> dict[str, Any]:
    """Decode a raw alert line, returning ``{}`` when it is not a JSON object."""
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}
