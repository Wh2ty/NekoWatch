"""Real-time HTTP/API import: poll external services into the ingest queue.

Supported producers:

* **wazuh** — Wazuh Manager REST API (``/security/user/authenticate`` + ``/alerts``)
* **generic** — any HTTP endpoint returning a JSON array, NDJSON, or a nested
  list addressed by ``items_path`` (Elastic/OpenSearch-style responses work)

Push ingest (``POST /api/v1/ingest/alerts``) lives in :mod:`routers.ingest` and
also calls :meth:`IngestionService.accept_payloads`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from core.api_sources_config import ApiSource, load_api_sources_config
from core.config import Settings
from domain.queries import ApiIngestStatus, ApiSourceStatus
from services.ingestion import IngestionService

logger = logging.getLogger("nekowatch.api_ingest")


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _dig(data: Any, path: str) -> Any:
    """Resolve a dotted path like ``data.affected_items``."""
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@dataclass
class _PollerState:
    source: ApiSource
    fetched: int = 0
    accepted: int = 0
    skipped: int = 0
    errors: int = 0
    last_poll_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    cursor: str | None = None
    jwt: str | None = None
    jwt_expires_at: float = 0.0
    seen_ids: set[str] = field(default_factory=set)


class ApiIngestService:
    """Background pollers that pull alerts from HTTP APIs into ingestion."""

    def __init__(
        self,
        settings: Settings,
        ingestion: IngestionService,
        sources: list[ApiSource] | None = None,
    ) -> None:
        self._settings = settings
        self._ingestion = ingestion
        resolved = (
            sources
            if sources is not None
            else load_api_sources_config(settings.sources_config)
        )
        self._states: dict[str, _PollerState] = {
            src.name: _PollerState(source=src) for src in resolved
        }
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stopping = asyncio.Event()
        self._ready = False
        self._clients: dict[bool, httpx.AsyncClient] = {}

    @property
    def enabled(self) -> bool:
        return self._settings.api_ingest_enabled

    @property
    def running(self) -> bool:
        return any(not t.done() for t in self._tasks.values()) and not self._stopping.is_set()

    @property
    def sources(self) -> list[ApiSource]:
        return [state.source for state in self._states.values()]

    async def start(self) -> None:
        """Launch poll loops for YAML sources; stay ready for live connect."""
        if not self._settings.api_ingest_enabled:
            logger.info("api_ingest_disabled")
            return

        self._stopping.clear()
        self._ready = True
        for state in self._states.values():
            self._spawn(state)
        logger.info(
            "api_ingest_started",
            extra={"sources": [s.name for s in self.sources]},
        )

    async def stop(self) -> None:
        """Cancel pollers and close HTTP clients."""
        self._ready = False
        if not self._tasks and not self._clients:
            self._stopping.set()
            return
        self._stopping.set()
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
        logger.info("api_ingest_stopped")

    def _spawn(self, state: _PollerState) -> None:
        """Start (or restart) the poll loop for one source."""
        name = state.source.name
        old = self._tasks.pop(name, None)
        if old is not None and not old.done():
            old.cancel()
        self._tasks[name] = asyncio.create_task(
            self._poll_loop(state),
            name=f"nekowatch-api-{name}",
        )

    async def connect_live(
        self,
        *,
        url: str,
        source_type: str = "generic",
        token: str = "",
        username: str = "",
        password: str = "",
        poll_interval: float = 5.0,
        verify_ssl: bool = False,
        name: str = "live",
    ) -> ApiSourceStatus:
        """Connect an API URL from the UI and start polling immediately."""
        if not self._settings.api_ingest_enabled:
            raise RuntimeError("api_ingest_disabled")

        cleaned = url.strip().rstrip("/")
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("url_must_start_with_http")

        kind = (source_type or "generic").lower().strip()
        if kind not in {"wazuh", "generic"}:
            raise ValueError("invalid_source_type")

        # Replace any previous live connection with the same name.
        await self.disconnect(name, missing_ok=True)

        if not self._ready:
            self._stopping.clear()
            self._ready = True

        source = ApiSource(
            name=name,
            type=kind,  # type: ignore[arg-type]
            url=cleaned,
            description="Подключено из интерфейса",
            poll_interval=max(1.0, float(poll_interval)),
            timeout=self._settings.api_ingest_timeout,
            verify_ssl=bool(verify_ssl),
            token=(token or "").strip(),
            username=(username or "").strip(),
            password=(password or "").strip(),
            items_path="data.affected_items" if kind == "wazuh" else "",
            response_format="wazuh" if kind == "wazuh" else "json_array",
            max_batch=self._settings.api_ingest_max_batch,
        )
        state = _PollerState(source=source)
        self._states[name] = state
        self._spawn(state)

        # Immediate first pull so the user sees data without waiting.
        try:
            await self._poll_source(state)
        except Exception as exc:  # noqa: BLE001
            state.errors += 1
            state.last_error = str(exc)[:500]
            logger.warning(
                "live_connect_first_poll_failed",
                extra={"source": name, "error": state.last_error},
            )

        logger.info("api_live_connected", extra={"name": name, "url": cleaned, "type": kind})
        return self._status_for(state)

    async def disconnect(self, name: str = "live", *, missing_ok: bool = False) -> None:
        """Stop a live/YAML poller by name."""
        task = self._tasks.pop(name, None)
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if name in self._states:
            del self._states[name]
        elif not missing_ok:
            raise KeyError(name)
        logger.info("api_source_disconnected", extra={"name": name})

    async def poll_once(self, name: str) -> ApiSourceStatus:
        """Run a single poll for ``name`` (manual trigger from the UI/API)."""
        state = self._states.get(name)
        if state is None:
            raise KeyError(name)
        await self._poll_source(state)
        return self._status_for(state)

    def status(self) -> ApiIngestStatus:
        """Snapshot for ``/api/v1/ingest/status`` and ingestion health."""
        token = (self._settings.ingest_push_token or "").strip()
        return ApiIngestStatus(
            enabled=self._settings.api_ingest_enabled,
            running=self.running,
            push_enabled=self._settings.ingest_push_enabled,
            push_auth_required=bool(token),
            sources=[self._status_for(state) for state in self._states.values()],
        )

    def _status_for(self, state: _PollerState) -> ApiSourceStatus:
        src = state.source
        task = self._tasks.get(src.name)
        task_running = task is not None and not task.done()
        return ApiSourceStatus(
            name=src.name,
            type=src.type,
            url=src.url,
            enabled=self._settings.api_ingest_enabled,
            running=task_running,
            poll_interval=src.poll_interval,
            fetched=state.fetched,
            accepted=state.accepted,
            skipped=state.skipped,
            errors=state.errors,
            last_poll_at=state.last_poll_at,
            last_success_at=state.last_success_at,
            last_error=state.last_error,
            cursor=state.cursor,
        )

    async def _poll_loop(self, state: _PollerState) -> None:
        """Keep polling one source until stopped or cancelled."""
        while not self._stopping.is_set():
            try:
                await self._poll_source(state)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                state.errors += 1
                state.last_error = str(exc)[:500]
                logger.exception(
                    "api_poll_failed",
                    extra={"source": state.source.name},
                )
            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=state.source.poll_interval,
                )
                return
            except asyncio.TimeoutError:
                continue

    async def _poll_source(self, state: _PollerState) -> None:
        """Fetch → parse → enqueue for one source."""
        state.last_poll_at = _utc_now()
        if state.source.type == "wazuh":
            payloads = await self._fetch_wazuh(state)
        else:
            payloads = await self._fetch_generic(state)

        if not payloads:
            state.last_success_at = _utc_now()
            state.last_error = None
            return

        # Deduplicate by alert id within a sliding window.
        fresh: list[dict[str, Any] | str] = []
        for item in payloads:
            alert_id = ""
            if isinstance(item, dict):
                alert_id = str(item.get("id") or item.get("alert_id") or "")
            if alert_id and alert_id in state.seen_ids:
                state.skipped += 1
                continue
            if alert_id:
                state.seen_ids.add(alert_id)
            fresh.append(item)

        # Bound memory of seen ids.
        if len(state.seen_ids) > 20_000:
            # Drop oldest half (sets are unordered — rebuild from recent batch).
            recent = {
                str(i.get("id") or i.get("alert_id") or "")
                for i in fresh
                if isinstance(i, dict)
            }
            state.seen_ids = {x for x in recent if x}

        result = await self._ingestion.accept_payloads(
            fresh,
            source_key=f"api:{state.source.name}",
            format="ndjson",
        )
        state.fetched += len(payloads)
        state.accepted += result.accepted
        state.skipped += result.skipped
        state.last_success_at = _utc_now()
        state.last_error = None

        # Advance cursor from the newest timestamp when present.
        newest = self._newest_timestamp(payloads)
        if newest:
            state.cursor = newest

        logger.info(
            "api_poll_ok",
            extra={
                "source": state.source.name,
                "fetched": len(payloads),
                "accepted": result.accepted,
                "skipped": result.skipped,
            },
        )

    @staticmethod
    def _newest_timestamp(payloads: list[Any]) -> str | None:
        best: str | None = None
        for item in payloads:
            if not isinstance(item, dict):
                continue
            ts = item.get("timestamp")
            if isinstance(ts, str) and (best is None or ts > best):
                best = ts
        return best

    def _http(self, *, verify_ssl: bool) -> httpx.AsyncClient:
        """Shared client per TLS-verify mode (httpx sets verify on the client)."""
        client = self._clients.get(verify_ssl)
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._settings.api_ingest_timeout),
                follow_redirects=True,
                verify=verify_ssl,
            )
            self._clients[verify_ssl] = client
        return client

    async def _fetch_wazuh(self, state: _PollerState) -> list[Any]:
        """Authenticate (JWT) and pull ``/alerts`` from a Wazuh manager."""
        src = state.source
        client = self._http(verify_ssl=src.verify_ssl)
        token = await self._wazuh_token(state, client)
        params: dict[str, str] = {
            "limit": str(min(src.max_batch, 500)),
            "sort": "-timestamp",
            **src.params,
        }
        if state.cursor and src.cursor_param:
            params[src.cursor_param] = state.cursor
        elif state.cursor:
            # Wazuh query language: only alerts newer than the last cursor.
            params["q"] = f"timestamp>{state.cursor}"

        url = f"{src.url.rstrip('/')}/alerts"
        headers = {"Authorization": f"Bearer {token}", **src.headers}
        response = await client.request(
            "GET",
            url,
            params=params,
            headers=headers,
            timeout=src.timeout,
        )
        response.raise_for_status()
        data = response.json()
        items = _dig(data, src.items_path or "data.affected_items")
        if not isinstance(items, list):
            return []
        return items[: src.max_batch]

    async def _wazuh_token(
        self, state: _PollerState, client: httpx.AsyncClient
    ) -> str:
        """Return a cached JWT or authenticate with basic auth / static token."""
        src = state.source
        if src.token:
            return src.token
        if state.jwt and time.monotonic() < state.jwt_expires_at:
            return state.jwt
        if not src.username or not src.password:
            raise RuntimeError(
                f"api source {src.name!r}: set username/password or token "
                f"(env NEKOWATCH_API_SOURCE_{src.name.upper()}_PASSWORD)"
            )

        url = f"{src.url.rstrip('/')}/security/user/authenticate"
        response = await client.post(
            url,
            auth=(src.username, src.password),
            headers=src.headers,
            timeout=src.timeout,
        )
        response.raise_for_status()
        body = response.json()
        token = _dig(body, "data.token") or body.get("token")
        if not token:
            raise RuntimeError(f"wazuh auth for {src.name!r} returned no token")
        state.jwt = str(token)
        # Wazuh JWTs typically last ~15 minutes; refresh a bit earlier.
        state.jwt_expires_at = time.monotonic() + 12 * 60
        return state.jwt

    async def _fetch_generic(self, state: _PollerState) -> list[Any]:
        """GET/POST a generic HTTP endpoint and extract alert payloads."""
        src = state.source
        client = self._http(verify_ssl=src.verify_ssl)
        headers = dict(src.headers)
        if src.token and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {src.token}"

        params = dict(src.params)
        if state.cursor and src.cursor_param:
            params[src.cursor_param] = state.cursor

        auth = None
        if src.username and src.password:
            auth = (src.username, src.password)

        response = await client.request(
            src.method,
            src.url,
            params=params or None,
            headers=headers,
            auth=auth,
            timeout=src.timeout,
        )
        response.raise_for_status()

        fmt = src.response_format
        if fmt == "ndjson":
            items: list[Any] = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    items.append(line)
            return items[: src.max_batch]

        data = response.json()
        if fmt == "wazuh" or src.items_path:
            items = _dig(data, src.items_path or "data.affected_items")
            if isinstance(items, list):
                return items[: src.max_batch]
            return []

        if isinstance(data, list):
            return data[: src.max_batch]
        if isinstance(data, dict):
            for key in ("alerts", "items", "events", "data", "results"):
                val = data.get(key)
                if isinstance(val, list):
                    return val[: src.max_batch]
        return []
