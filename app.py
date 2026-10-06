"""NekoWatch — SOC log analyzer for Logener/Wazuh alert streams.

Application factory and lifespan. The composition root lives in
:mod:`core.container`; this module only wires HTTP concerns (routers, CORS,
static files, error handling) and owns startup/shutdown ordering.

Run locally::

    uvicorn app:app --reload
"""

# `from __future__ import annotations` must come after the module docstring —
# a plain string literal placed after it is just a statement, not a
# docstring, so `app.__doc__` (and anything introspecting it, e.g. Sphinx
# or `python -c "import app; help(app)"`) used to come back empty.
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from core.config import Settings, get_settings
from core.container import ServiceContainer
from routers import analytics, correlation, export, ingest, logener, logs, pages, rules
from routers import status as status_router
from routers import stream, system, triage

try:
    from routers import ai as ai_router
except Exception:  # noqa: BLE001 - AI is optional; never block log generation
    ai_router = None
    logging.getLogger("nekowatch").warning(
        "ai_router_unavailable — GigaChat endpoints disabled"
    )

logger = logging.getLogger("nekowatch")


def _configure_logging(settings: Settings) -> None:
    """Send structured-ish logs to stdout at a sane level."""
    level = logging.DEBUG if settings.environment == "development" else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)-28s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the analyzer stack, then tear it down deterministically."""
    settings = get_settings()
    _configure_logging(settings)
    logger.info("nekowatch_starting", extra={"version": settings.app_version})

    container = await ServiceContainer.create(settings)
    app.state.container = container
    logger.info(
        "nekowatch_ready",
        extra={
            "log_file": str(settings.log_file),
            "database": str(settings.database_path),
        },
    )
    try:
        yield
    finally:
        app.state.container = None
        await container.shutdown()
        try:
            from soc_ai_analyzer import close_shared_gigachat

            await close_shared_gigachat()
        except Exception:  # noqa: BLE001 - optional AI teardown
            logger.debug("gigachat_shutdown_skipped", exc_info=True)
        logger.info("nekowatch_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    resolved = settings or get_settings()

    # Здесь создается рабочее приложение
    app = FastAPI(
        title=resolved.app_name,
        version=resolved.app_version,
        description=(
            "SOC log analyzer for Wazuh-format alert streams: live file/API "
            "ingestion, HTTP push import, filtered search, ATT&CK enrichment, "
            "analytics, correlation, triage and streaming export."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    for module in (
        system,
        logs,
        analytics,
        correlation,
        triage,
        export,
        stream,
        ingest,
        logener,
        pages,
        status_router,
        rules,
    ):
        app.include_router(module.router)

    if ai_router is not None:
        app.include_router(ai_router.router)

    # Правильное монтирование статики (в зависимости от настроек)
    static_dir = resolved.static_dir
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        """Surface allow-list violations as 400 instead of 500."""
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    current = get_settings()
    uvicorn.run(
        "app:app",
        host=current.host,
        port=current.port,
        reload=current.environment == "development",
    )