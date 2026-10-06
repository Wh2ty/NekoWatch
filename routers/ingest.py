"""Real-time alert import: HTTP push + API poller control.

Push alerts into the shared ingestion pipeline::

    POST /api/v1/ingest/alerts
    Content-Type: application/json
    Body: one Wazuh alert, an array of alerts, or NDJSON lines

Optional auth: set ``NEKOWATCH_INGEST_PUSH_TOKEN`` and send
``X-NekoWatch-Token: <token>`` (or ``Authorization: Bearer <token>``).
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from domain.queries import ApiIngestStatus, ApiSourceStatus, IngestAcceptResult
from routers.dependencies import ContainerDep

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


class IngestTextBody(BaseModel):
    """Manual paste from the UI: raw NDJSON or a JSON array string."""

    text: str = Field(..., min_length=1, description="NDJSON lines or a JSON array.")
    source: str = Field(default="push", max_length=64)


class ConnectLiveBody(BaseModel):
    """Connect an external API URL from the UI and start live polling."""

    url: str = Field(..., min_length=8, max_length=2000, description="HTTP(S) API URL.")
    type: str = Field(
        default="generic",
        description="generic — JSON/NDJSON endpoint; wazuh — Wazuh Manager base URL.",
    )
    token: str = Field(default="", max_length=4000, description="Bearer token (optional).")
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=256)
    poll_interval: float = Field(default=5.0, ge=1.0, le=300.0)
    verify_ssl: bool = Field(default=False)
    name: str = Field(default="live", max_length=64)


def _check_push_auth(
    container: ContainerDep,
    x_neko_watch_token: str | None,
    authorization: str | None,
) -> None:
    expected = (container.settings.ingest_push_token or "").strip()
    if not expected:
        return
    provided = (x_neko_watch_token or "").strip()
    if not provided and authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        else:
            provided = auth
    if provided != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_ingest_token",
        )


def _extract_payloads(body: Any) -> list[Any]:
    """Normalize request body into a list of alert dicts / NDJSON strings."""
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        # Nested wrappers used by some SIEM / webhook relays.
        for key in ("alerts", "items", "events", "data", "records"):
            nested = body.get(key)
            if isinstance(nested, list):
                return nested
        return [body]
    if isinstance(body, str):
        return _payloads_from_text(body)
    return []


def _payloads_from_text(text: str) -> list[Any]:
    text = text.strip()
    if not text:
        return []
    # Prefer a single JSON value (object or array).
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return _extract_payloads(parsed)

    # Fall back to NDJSON (one JSON object per line).
    items: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            items.append(line)
    return items


@router.get(
    "/status",
    response_model=ApiIngestStatus,
    summary="API / push ingest status",
)
async def ingest_status(container: ContainerDep) -> ApiIngestStatus:
    """Push gate + configured HTTP pollers."""
    return container.api_ingest.status()


@router.post(
    "/alerts",
    response_model=IngestAcceptResult,
    summary="Push Wazuh alerts (real-time)",
    status_code=status.HTTP_202_ACCEPTED,
)
async def push_alerts(
    request: Request,
    container: ContainerDep,
    x_neko_watch_token: str | None = Header(default=None, alias="X-NekoWatch-Token"),
    authorization: str | None = Header(default=None),
) -> IngestAcceptResult:
    """Accept one alert, an array, or NDJSON into the live pipeline."""
    if not container.settings.ingest_push_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ingest_push_disabled",
        )
    _check_push_auth(container, x_neko_watch_token, authorization)

    content_type = (request.headers.get("content-type") or "").lower()
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="empty_body")

    text = raw.decode("utf-8", errors="replace")
    if "ndjson" in content_type or "x-ndjson" in content_type:
        payloads = _payloads_from_text(text)
    else:
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            payloads = _payloads_from_text(text)
        else:
            payloads = _extract_payloads(body)

    if not payloads:
        raise HTTPException(status_code=400, detail="no_alerts_in_body")

    max_batch = container.settings.api_ingest_max_batch
    if len(payloads) > max_batch:
        raise HTTPException(
            status_code=413,
            detail=f"batch_too_large:max={max_batch}",
        )

    return await container.ingestion.accept_payloads(
        payloads,
        source_key="api:push",
        format="ndjson",
    )


@router.post(
    "/text",
    response_model=IngestAcceptResult,
    summary="Import pasted NDJSON / JSON from the UI",
    status_code=status.HTTP_202_ACCEPTED,
)
async def push_text(
    body: IngestTextBody,
    container: ContainerDep,
    x_neko_watch_token: str | None = Header(default=None, alias="X-NekoWatch-Token"),
    authorization: str | None = Header(default=None),
) -> IngestAcceptResult:
    """Same pipeline as ``/alerts``, convenience shape for the Generator page."""
    if not container.settings.ingest_push_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ingest_push_disabled",
        )
    _check_push_auth(container, x_neko_watch_token, authorization)

    payloads = _payloads_from_text(body.text)
    if not payloads:
        raise HTTPException(status_code=400, detail="no_alerts_in_body")

    max_batch = container.settings.api_ingest_max_batch
    if len(payloads) > max_batch:
        raise HTTPException(
            status_code=413,
            detail=f"batch_too_large:max={max_batch}",
        )

    source = body.source.strip() or "push"
    return await container.ingestion.accept_payloads(
        payloads,
        source_key=source,
        format="ndjson",
    )


@router.post(
    "/connect",
    response_model=ApiSourceStatus,
    summary="Connect API URL and start live polling",
)
async def connect_live(body: ConnectLiveBody, container: ContainerDep) -> ApiSourceStatus:
    """UI helper: paste a URL, press connect, alerts start flowing in."""
    try:
        return await container.api_ingest.connect_live(
            url=body.url,
            source_type=body.type,
            token=body.token,
            username=body.username,
            password=body.password,
            poll_interval=body.poll_interval,
            verify_ssl=body.verify_ssl,
            name=(body.name or "live").strip() or "live",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post(
    "/disconnect",
    summary="Disconnect a live API source",
)
async def disconnect_live(
    container: ContainerDep,
    name: str = "live",
) -> dict[str, str]:
    """Stop polling the live (or named) API source."""
    try:
        await container.api_ingest.disconnect(name)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown_api_source:{name}",
        ) from exc
    return {"status": "disconnected", "name": name}


@router.post(
    "/sources/{name}/poll",
    response_model=ApiSourceStatus,
    summary="Trigger one poll for a configured API source",
)
async def poll_source(name: str, container: ContainerDep) -> ApiSourceStatus:
    """Force an immediate fetch from ``api_sources`` entry ``name``."""
    try:
        return await container.api_ingest.poll_once(name)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown_api_source:{name}",
        ) from exc
