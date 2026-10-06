"""Load log-source definitions from ``config/sources.yaml``.

The YAML file is the operator-facing place to point NekoWatch at real Wazuh
paths (``alerts.json``, ``alerts.log``, ``archives.json``) or the Logener demo
file — without rebuilding the app.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml

from core.config import BASE_DIR

logger = logging.getLogger("nekowatch.sources")

SourcesFormat = Literal["ndjson", "plain"]


@dataclass(frozen=True, slots=True)
class LogSource:
    """One tailed file."""

    name: str
    path: Path
    format: SourcesFormat
    description: str = ""


def _default_sources_path() -> Path:
    return BASE_DIR / "config" / "sources.yaml"


def _expand_path(raw: str | Path) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (BASE_DIR / path).resolve()
    return path


def load_sources_config(path: Path | None = None) -> list[LogSource]:
    """Parse YAML and return the *active* sources (may be empty → caller fallback)."""
    config_path = path or _default_sources_path()
    if not config_path.exists():
        logger.warning("sources_config_missing", extra={"path": str(config_path)})
        return []

    data: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    catalogue: dict[str, Any] = data.get("sources") or {}
    active = data.get("active") or []
    if isinstance(active, str):
        active = [active]

    resolved: list[LogSource] = []
    for name in active:
        entry = catalogue.get(name)
        if not entry:
            logger.error("unknown_source_name", extra={"name": name})
            continue
        fmt = str(entry.get("format", "ndjson")).lower()
        if fmt not in {"ndjson", "plain"}:
            logger.error("invalid_source_format", extra={"name": name, "format": fmt})
            continue
        resolved.append(
            LogSource(
                name=str(name),
                path=_expand_path(entry["path"]),
                format=fmt,  # type: ignore[arg-type]
                description=str(entry.get("description") or ""),
            )
        )
    logger.info(
        "sources_loaded",
        extra={
            "config": str(config_path),
            "count": len(resolved),
            "names": [s.name for s in resolved],
        },
    )
    return resolved


@lru_cache(maxsize=1)
def get_active_sources() -> tuple[LogSource, ...]:
    """Process-wide active sources (tuple for hashability/cache)."""
    return tuple(load_sources_config())
