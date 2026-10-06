"""Control endpoints for the Logener alert generator.

Kept at the original ``/logener`` prefix so existing clients keep working. The
one behavioural change: ``reset`` now defaults to the configured
``NEKOWATCH_GENERATOR_RESET_ON_START`` (``false``), because truncating the alert
file on every start silently destroyed the history the analyzer had indexed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from routers.dependencies import ContainerDep

logger = logging.getLogger("nekowatch.logener")

router = APIRouter(prefix="/logener", tags=["logener"])

#: Exact phrase the client must send to authorize a destructive full reset.
FULL_RESET_CONFIRM = "УДАЛИТЬ ВСЁ"


class FullResetRequest(BaseModel):
    """Body for ``POST /logener/full-reset``."""

    confirm: str = Field(
        ...,
        description=f'Must be exactly "{FULL_RESET_CONFIRM}" (case-sensitive).',
    )


@router.get("/status", summary="Generator status")
async def get_status(container: ContainerDep) -> dict[str, Any]:
    """Whether the generator runs, how many events it produced and where."""
    return container.generator.status()


@router.post("/start", summary="Start the generator")
async def start_generator(
    container: ContainerDep,
    reset: Annotated[
        bool | None,
        Query(
            description="Truncate the alert file first. Defaults to the "
            "NEKOWATCH_GENERATOR_RESET_ON_START setting (false)."
        ),
    ] = None,
) -> dict[str, Any]:
    """Start generating alerts in the background.

    Raises:
        HTTPException: 409 when the generator is already running.
    """
    should_reset = (
        container.settings.generator_reset_on_start if reset is None else reset
    )
    if not container.generator.start(reset=should_reset):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="generator_already_running"
        )
    return container.generator.status()


@router.post("/stop", summary="Stop the generator")
async def stop_generator(container: ContainerDep) -> dict[str, Any]:
    """Stop generating alerts.

    Raises:
        HTTPException: 409 when the generator is not running.
    """
    if not container.generator.stop():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="generator_not_running"
        )
    return container.generator.status()


@router.post("/full-reset", summary="Wipe database + alert JSON file")
async def full_reset(
    container: ContainerDep, body: FullResetRequest
) -> dict[str, Any]:
    """Stop the generator, truncate the NDJSON alert file and wipe SQLite data.

    Requires ``confirm`` to match :data:`FULL_RESET_CONFIRM` exactly so a
    stray click / script cannot erase production data.
    """
    if body.confirm.strip() != FULL_RESET_CONFIRM:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'confirm_mismatch: type exactly "{FULL_RESET_CONFIRM}"',
        )

    generator_was_running = container.generator.is_running
    if generator_was_running:
        container.generator.stop()

    log_path = Path(container.settings.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")

    # Keep generator counters aligned with the empty file (do not restart).
    container.generator.reset_counters()

    wiped = await container.repository.wipe_all()
    await container.ingestion.reset_after_wipe()

    logger.warning(
        "full_reset_completed",
        extra={
            "log_file": str(log_path),
            "database": str(container.settings.database_path),
            "wiped": wiped,
            "generator_was_running": generator_was_running,
        },
    )
    return {
        "ok": True,
        "confirm": FULL_RESET_CONFIRM,
        "log_file": str(log_path),
        "log_file_size": log_path.stat().st_size,
        "database": str(container.settings.database_path),
        "wiped": wiped,
        "generator_stopped": generator_was_running,
        "ingestion": (await container.ingestion.status()).model_dump(mode="json"),
    }
