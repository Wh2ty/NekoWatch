"""Load real-time HTTP/API ingest sources from ``config/sources.yaml``.

API sources sit alongside file tails. Each active entry becomes a background
poller that feeds the shared :class:`~services.ingestion.IngestionService`
queue — same parser, LiveHub, rules and SQLite path as disk files.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from core.config import BASE_DIR

logger = logging.getLogger("nekowatch.api_sources")

ApiSourceType = Literal["wazuh", "generic"]
ApiResponseFormat = Literal["json_array", "ndjson", "wazuh"]


@dataclass(frozen=True, slots=True)
class ApiSource:
    """One HTTP/API producer of Wazuh-shaped alerts."""

    name: str
    type: ApiSourceType
    url: str
    description: str = ""
    poll_interval: float = 5.0
    timeout: float = 30.0
    verify_ssl: bool = True
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    username: str = ""
    password: str = ""
    token: str = ""
    # For generic JSON: dotted path to the list of alerts (e.g. data.affected_items).
    items_path: str = ""
    response_format: ApiResponseFormat = "json_array"
    # Query/body extras for the poll request.
    params: dict[str, str] = field(default_factory=dict)
    # When set, append ``?{cursor_param}=<last_cursor>`` after the first poll.
    cursor_param: str = ""
    # Max alerts accepted per poll cycle.
    max_batch: int = 500


def _default_sources_path() -> Path:
    return BASE_DIR / "config" / "sources.yaml"


def _env_override(name: str, field_name: str) -> str:
    """``NEKOWATCH_API_SOURCE_<NAME>_<FIELD>`` override (password/token/url)."""
    key = f"NEKOWATCH_API_SOURCE_{name.upper().replace('-', '_')}_{field_name.upper()}"
    return os.environ.get(key, "").strip()


def _as_str_dict(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v is not None}


def _parse_source(name: str, entry: dict[str, Any], defaults: dict[str, Any]) -> ApiSource | None:
    src_type = str(entry.get("type") or "generic").lower()
    if src_type not in {"wazuh", "generic"}:
        logger.error("invalid_api_source_type", extra={"name": name, "type": src_type})
        return None

    base_url = (
        _env_override(name, "url")
        or str(entry.get("url") or entry.get("base_url") or "").rstrip("/")
    )
    if not base_url:
        logger.error("api_source_missing_url", extra={"name": name})
        return None

    username = _env_override(name, "username") or str(entry.get("username") or "")
    password = _env_override(name, "password") or str(entry.get("password") or "")
    token = _env_override(name, "token") or str(entry.get("token") or "")

    resp_fmt = str(entry.get("response_format") or ("wazuh" if src_type == "wazuh" else "json_array"))
    if resp_fmt not in {"json_array", "ndjson", "wazuh"}:
        logger.error("invalid_api_response_format", extra={"name": name, "format": resp_fmt})
        return None

    poll_interval = float(
        entry.get("poll_interval", defaults.get("poll_interval", 5.0))
    )
    timeout = float(entry.get("timeout", defaults.get("timeout", 30.0)))
    max_batch = int(entry.get("max_batch", defaults.get("max_batch", 500)))

    items_path = str(entry.get("items_path") or "")
    if src_type == "wazuh" and not items_path:
        items_path = "data.affected_items"

    return ApiSource(
        name=str(name),
        type=src_type,  # type: ignore[arg-type]
        url=base_url,
        description=str(entry.get("description") or ""),
        poll_interval=max(1.0, poll_interval),
        timeout=max(1.0, timeout),
        verify_ssl=bool(entry.get("verify_ssl", True)),
        method=str(entry.get("method") or "GET").upper(),
        headers=_as_str_dict(entry.get("headers")),
        username=username,
        password=password,
        token=token,
        items_path=items_path,
        response_format=resp_fmt,  # type: ignore[arg-type]
        params=_as_str_dict(entry.get("params")),
        cursor_param=str(entry.get("cursor_param") or ""),
        max_batch=max(1, max_batch),
    )


def load_api_sources_config(path: Path | None = None) -> list[ApiSource]:
    """Parse YAML and return *active* API sources (may be empty)."""
    config_path = path or _default_sources_path()
    if not config_path.exists():
        return []

    data: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    catalogue: dict[str, Any] = data.get("api_sources") or {}
    active = data.get("api_active") or []
    if isinstance(active, str):
        active = [active]
    defaults = data.get("api_defaults") or {}

    resolved: list[ApiSource] = []
    for name in active:
        entry = catalogue.get(name)
        if not entry:
            logger.error("unknown_api_source_name", extra={"name": name})
            continue
        parsed = _parse_source(str(name), entry, defaults)
        if parsed is not None:
            resolved.append(parsed)

    logger.info(
        "api_sources_loaded",
        extra={
            "config": str(config_path),
            "count": len(resolved),
            "names": [s.name for s in resolved],
        },
    )
    return resolved
