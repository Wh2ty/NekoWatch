"""Streaming export of filtered alert sets.

Exports are generated incrementally: the repository yields records in
keyset-paginated chunks, each chunk is serialised into a small string buffer and
handed to Starlette's ``StreamingResponse``. Nothing accumulates, so exporting
a million rows costs roughly the same memory as exporting ten.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from core.config import Settings
from domain.models import CSV_COLUMNS, ExportFormat
from domain.queries import LogFilter
from repositories.base import LogRepository

logger = logging.getLogger("nekowatch.export")

_MEDIA_TYPES: dict[ExportFormat, str] = {
    ExportFormat.CSV: "text/csv; charset=utf-8",
    ExportFormat.JSON: "application/json; charset=utf-8",
    ExportFormat.JSONL: "application/x-ndjson; charset=utf-8",
}


class ExportService:
    """Builds CSV / JSON / NDJSON downloads from a filtered selection."""

    def __init__(self, repository: LogRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings

    # ------------------------------------------------------------- metadata
    @staticmethod
    def media_type(export_format: ExportFormat) -> str:
        """HTTP content type for a format."""
        return _MEDIA_TYPES[export_format]

    @staticmethod
    def filename(export_format: ExportFormat, prefix: str = "nekowatch") -> str:
        """Timestamped download filename."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = "ndjson" if export_format is ExportFormat.JSONL else export_format.value
        return f"{prefix}-alerts-{stamp}.{suffix}"

    # --------------------------------------------------------------- streams
    def stream(
        self,
        log_filter: LogFilter,
        export_format: ExportFormat,
        *,
        ecs: bool = False,
        ascending: bool = True,
    ) -> AsyncIterator[str]:
        """Return an async generator producing the export body.

        Args:
            log_filter: Selection to export.
            export_format: ``csv``, ``json`` or ``jsonl``.
            ecs: Emit Elastic Common Schema documents instead of flat records
                (JSON/NDJSON only; CSV is always flat).
            ascending: Chronological order when ``True``.
        """
        if export_format is ExportFormat.CSV:
            return self._stream_csv(log_filter, ascending=ascending)
        if export_format is ExportFormat.JSONL:
            return self._stream_jsonl(log_filter, ecs=ecs, ascending=ascending)
        return self._stream_json(log_filter, ecs=ecs, ascending=ascending)

    async def _stream_csv(
        self, log_filter: LogFilter, *, ascending: bool
    ) -> AsyncIterator[str]:
        """Yield RFC 4180 CSV: one header row, then the selection.

        Alert content comes from whoever is attacking the monitored network,
        not from a trusted analyst, so it must not be trusted to open safely
        in a spreadsheet either: a message/user/IP value starting with
        ``= + - @`` (or a tab/CR, which Excel also treats as a formula lead-in)
        is neutralised via :func:`_csv_safe` — the classic CSV/formula
        injection a SOC export must guard against.
        """
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer, fieldnames=list(CSV_COLUMNS), extrasaction="ignore"
        )
        writer.writeheader()
        yield _drain(buffer)

        rows = 0
        async for record in self._records(log_filter, ascending):
            row = {k: _csv_safe(v) for k, v in record.to_flat_dict().items()}
            writer.writerow(row)
            rows += 1
            if rows % self._settings.export_chunk_size == 0:
                yield _drain(buffer)

        tail = _drain(buffer)
        if tail:
            yield tail
        logger.info("export_completed", extra={"format": "csv", "rows": rows})

    async def _stream_json(
        self, log_filter: LogFilter, *, ecs: bool, ascending: bool
    ) -> AsyncIterator[str]:
        """Yield a single JSON document with an export metadata header.

        The envelope is written incrementally so the response starts flowing
        before the last row has been read from the database.
        """
        header = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema": "ecs-8.x" if ecs else "nekowatch-flat",
            "filter": log_filter.describe(),
        }
        yield "{" + f'"export": {json.dumps(header, ensure_ascii=False)}, "events": ['

        rows = 0
        async for record in self._records(log_filter, ascending):
            payload = record.to_ecs() if ecs else record.model_dump(mode="json")
            prefix = "" if rows == 0 else ","
            yield prefix + json.dumps(payload, ensure_ascii=False)
            rows += 1

        yield f'], "count": {rows}' + "}"
        logger.info("export_completed", extra={"format": "json", "rows": rows})

    async def _stream_jsonl(
        self, log_filter: LogFilter, *, ecs: bool, ascending: bool
    ) -> AsyncIterator[str]:
        """Yield newline-delimited JSON, one document per line."""
        rows = 0
        async for record in self._records(log_filter, ascending):
            payload = record.to_ecs() if ecs else record.model_dump(mode="json")
            yield json.dumps(payload, ensure_ascii=False) + "\n"
            rows += 1
        logger.info("export_completed", extra={"format": "jsonl", "rows": rows})

    def _records(self, log_filter: LogFilter, ascending: bool):
        """Repository cursor honouring the configured export row cap."""
        return self._repository.iter_records(
            log_filter,
            chunk_size=self._settings.export_chunk_size,
            max_rows=self._settings.export_max_rows,
            ascending=ascending,
        )


_FORMULA_LEAD_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Prefix a leading formula character so Excel/Sheets treat it as text.

    Only strings are affected; numbers, bools, ``None`` and the rest pass
    through untouched so the exported types stay faithful to the data.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_LEAD_CHARS):
        return "'" + value
    return value


def _drain(buffer: io.StringIO) -> str:
    """Take everything written so far and reset the buffer for reuse."""
    value = buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    return value
