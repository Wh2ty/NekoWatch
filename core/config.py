"""Application settings.

All values are overridable through environment variables (or a local ``.env``
file) using the ``NEKOWATCH_`` prefix, e.g.::

    export NEKOWATCH_LOG_FILE=/var/ossec/logs/alerts/alerts.json
    export NEKOWATCH_DATABASE_PATH=/var/lib/nekowatch/nekowatch.db
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration for the NekoWatch analyzer."""

    model_config = SettingsConfigDict(
        env_prefix="NEKOWATCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---------------------------------------------------------------- general
    app_name: str = "NekoWatch"
    app_version: str = "1.0.0"
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000

    # ------------------------------------------------------------- data paths
    log_file: Path = Field(
        default=Path("/tmp/wazuh_logs/wazuh_alerts.json"),
        description="Fallback NDJSON alert file when sources.yaml has no active "
        "entries. Prefer config/sources.yaml for real Wazuh paths.",
    )
    sources_config: Path = Field(
        default=BASE_DIR / "config" / "sources.yaml",
        description="YAML file listing Wazuh/Logener paths to tail.",
    )
    database_path: Path = Field(
        default=BASE_DIR / "data" / "nekowatch.db",
        description="SQLite database used as the analyzer's event store.",
    )

    # -------------------------------------------------------------- ingestion
    tail_poll_interval: float = Field(default=0.25, gt=0.0, le=5.0)
    ingest_queue_size: int = Field(default=10_000, ge=100)
    ingest_batch_size: int = Field(default=500, ge=1)
    ingest_flush_interval: float = Field(default=1.0, gt=0.0)
    ingest_from_start: bool = Field(
        default=True,
        description="On first run, read the alert file from the beginning "
        "instead of tailing only new lines.",
    )

    # ----------------------------------------------- real-time API import
    ingest_push_enabled: bool = Field(
        default=True,
        description="Accept POST /api/v1/ingest/alerts (HTTP push of Wazuh alerts).",
    )
    ingest_push_token: str = Field(
        default="",
        description="Shared secret for push ingest. Empty = no auth (dev only). "
        "Clients send X-NekoWatch-Token or Authorization: Bearer.",
    )
    api_ingest_enabled: bool = Field(
        default=True,
        description="Run background pollers for api_sources in sources.yaml.",
    )
    api_ingest_timeout: float = Field(
        default=30.0,
        gt=1.0,
        le=300.0,
        description="Default HTTP timeout (seconds) for API pollers.",
    )
    api_ingest_max_batch: int = Field(
        default=500,
        ge=1,
        le=5_000,
        description="Max alerts accepted per push request or poll cycle.",
    )

    # ------------------------------------------------------------- live stream
    live_buffer_size: int = Field(default=500, ge=1)
    live_max_clients: int = Field(default=50, ge=1)
    live_client_queue_size: int = Field(default=1_000, ge=10)
    live_heartbeat_interval: float = Field(default=15.0, gt=0.0)
    live_stats_interval: float = Field(default=1.0, gt=0.0)

    # --------------------------------------------------------------- generator
    generator_autostart: bool = Field(
        default=False,
        description="Start Logener automatically with the API. Off by default — "
        "start manually from the Generator page.",
    )
    generator_reset_on_start: bool = Field(
        default=False,
        description="Truncate the alert file when the generator starts. "
        "Disabled by default so restarts never destroy collected history.",
    )

    # --------------------------------------------------------------- retention
    retention_max_events: int = Field(
        default=0,
        ge=0,
        description="Prune oldest events beyond this count. 0 disables pruning.",
    )
    retention_interval: float = Field(default=300.0, gt=0.0)

    # ---------------------------------------------------------------- querying
    default_page_size: int = Field(default=100, ge=1)
    max_page_size: int = Field(default=1_000, ge=1)
    search_max_length: int = Field(default=200, ge=1)
    export_chunk_size: int = Field(default=1_000, ge=1)
    export_max_rows: int = Field(
        default=0,
        ge=0,
        description="Hard cap on exported rows. 0 means unlimited.",
    )

    # -------------------------------------------------------------------- http
    cors_origins: str = "*"

    # -------------------------------------------------------- status monitor
    status_monitor_enabled: bool = Field(
        default=True,
        description="Run source-timeout and LAN ping background loops.",
    )
    source_event_timeout_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Mark a source problematic when no events arrive for this long.",
    )
    source_timeout_check_interval: float = Field(default=15.0, gt=1.0)
    status_ping_interval: float = Field(default=30.0, gt=1.0)
    status_ping_timeout_ms: int = Field(default=1000, ge=200, le=10_000)
    status_ping_mock: bool = Field(
        default=True,
        description="Use deterministic mock ping results (safe for demos/CI). "
        "Set false to run real ICMP probes against LAN IPs.",
    )
    status_ping_concurrency: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Max concurrent ICMP probes per ping sweep.",
    )
    foreign_device_alert_cooldown: float = Field(
        default=300.0,
        ge=0.0,
        description="Seconds between repeat rogue-device alerts for the same agent.",
    )
    source_timeout_alert_cooldown: float = Field(
        default=120.0,
        ge=0.0,
        description="Seconds between repeat timeout alerts while still silent.",
    )
    source_recovery_notify: bool = Field(
        default=True,
        description="Emit a notification when a timed-out source resumes events.",
    )

    @field_validator("log_file", "database_path", "sources_config")
    @classmethod
    def _expand(cls, value: Path) -> Path:
        """Expand ``~`` and resolve relative paths against the project root."""
        expanded = value.expanduser()
        return expanded if expanded.is_absolute() else (BASE_DIR / expanded)

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins as a list (``*`` stays a single wildcard entry)."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def templates_dir(self) -> Path:
        """Directory holding Jinja2 templates."""
        return BASE_DIR / "templates"

    @property
    def static_dir(self) -> Path:
        """Directory holding static assets (CSS/JS)."""
        return BASE_DIR / "static"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
