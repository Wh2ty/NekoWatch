"""Composition root.

One place wires settings -> async SQLAlchemy repository -> services -> ingestion.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from core.config import Settings, get_settings
from logener import WazuhGenerator
from repositories.rules_repo import RulesRepository
from repositories.sqlalchemy_repo import SqlAlchemyLogRepository
from repositories.status_repo import StatusRepository
from services.analytics import AnalyticsService
from services.api_ingest import ApiIngestService
from services.correlation import CorrelationService
from services.export import ExportService
from services.ingestion import IngestionService
from services.live import LiveHub
from services.query import LogQueryService
from services.rule_engine import RuleEngine
from services.status_monitor import StatusMonitorService
from services.triage import TriageService

logger = logging.getLogger("nekowatch.container")


@dataclass(slots=True)
class ServiceContainer:
    """Application-wide singletons, created once per process."""

    settings: Settings
    repository: SqlAlchemyLogRepository
    hub: LiveHub
    ingestion: IngestionService
    api_ingest: ApiIngestService
    query: LogQueryService
    analytics: AnalyticsService
    correlation: CorrelationService
    triage: TriageService
    export: ExportService
    generator: WazuhGenerator
    status: StatusMonitorService
    rules: RuleEngine

    @classmethod
    async def create(cls, settings: Settings | None = None) -> "ServiceContainer":
        """Build and start every component."""
        resolved = settings or get_settings()

        repository = SqlAlchemyLogRepository(resolved.database_path)
        await repository.initialize()

        status_repo = StatusRepository(repository.database)
        hub = LiveHub(resolved)
        status = StatusMonitorService(resolved, status_repo, hub=hub)

        rules_repo = RulesRepository(repository.database)
        rules = RuleEngine(rules_repo, status_repo, hub=hub)

        ingestion = IngestionService(
            resolved,
            repository,
            hub,
            status_monitor=status,
            rule_engine=rules,
        )
        api_ingest = ApiIngestService(resolved, ingestion)
        # Keep settings.log_file aligned with the primary tailed path so Logener,
        # templates and legacy status fields stay consistent.
        primary = ingestion.primary_path
        resolved.log_file = primary
        generator = WazuhGenerator(output_path=Path(primary))

        container = cls(
            settings=resolved,
            repository=repository,
            hub=hub,
            ingestion=ingestion,
            api_ingest=api_ingest,
            query=LogQueryService(repository, resolved),
            analytics=AnalyticsService(repository, resolved),
            correlation=CorrelationService(repository, resolved),
            triage=TriageService(repository, resolved),
            export=ExportService(repository, resolved),
            generator=generator,
            status=status,
            rules=rules,
        )

        await rules.start()
        await status.start()
        await ingestion.start()
        await api_ingest.start()

        # Optional: generator stays stopped unless NEKOWATCH_GENERATOR_AUTOSTART=true.
        if resolved.generator_autostart:
            started = generator.start(reset=resolved.generator_reset_on_start)
            logger.info(
                "generator_autostarted" if started else "generator_already_running",
                extra={
                    "output": str(generator.output_path),
                    "reset": resolved.generator_reset_on_start,
                    "running": generator.is_running,
                },
            )
            if not generator.is_running:
                generator.start(reset=False)
                logger.warning(
                    "generator_restarted_after_failed_autostart",
                    extra={"running": generator.is_running},
                )

        return container

    async def shutdown(self) -> None:
        """Tear everything down in reverse order."""
        self.generator.stop()
        await self.api_ingest.stop()
        await self.status.stop()
        await self.rules.stop()
        await self.hub.shutdown()
        await self.ingestion.stop()
        await self.repository.close()
        logger.info("container_shutdown_complete")
