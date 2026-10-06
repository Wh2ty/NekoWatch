"""GigaChat-backed SOC analyst for NekoWatch.

Takes a batch of security alerts, asks GigaChat (Pro/Max) for a structured
correlation assessment with infrastructure recommendations, and returns a
validated :class:`SOCAnalysisResponse`.

Credentials are read from the environment (``GIGACHAT_CREDENTIALS``,
``GIGACHAT_SCOPE``) — never hard-code secrets in source.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger("nekowatch.soc_ai")

DEFAULT_MODEL = "GigaChat-Pro"
FALLBACK_MODEL = "GigaChat-Max"
DEFAULT_TIMEOUT = 90.0
MAX_EVENTS_PER_REQUEST = 50
_PROJECT_ROOT = Path(__file__).resolve().parent

_SYSTEM_PROMPT = """\
Ты — старший аналитик SOC (Security Operations Center) и инженер по реагированию.
Тебе передаётся пакет security-алертов в формате JSON (Wazuh / Logener / NekoWatch).

Твоя задача — корреляционный анализ и практические рекомендации по инфраструктуре.

ОБЯЗАТЕЛЬНО:
1. Определи, есть ли атака / цепочка компрометации, или это шум.
2. Оцени confidence_score от 0.0 до 1.0.
3. Сформулируй краткое summary на русском.
4. Укажи релевантные MITRE ATT&CK tactics (человекочитаемые имена, напр. "Initial Access").
5. Выдели инциденты: root cause, affected assets, attack_chain по шагам.
6. Дай infrastructure_recommendations с приоритетом IMMEDIATE / HARDENING и
   action_type CONTAINMENT / PREVENTION / DETECTION / ERADICATION.
7. В commands_or_config пиши реальные команды/конфиги (firewall, AD, sshd, Wazuh и т.п.),
   опираясь на IP / пользователей / хосты из входных событий. Не выдумывай IOC,
   которых нет во входных данных (если данных мало — явно скажи об этом в summary).

Отвечай СТРОГО одним JSON-объектом без markdown и без code fences.
Пиши тексты (summary, root_cause, recommendation, attack_chain) на русском.

Схема ответа (пример структуры):
{
  "correlation_analysis": {
    "attack_detected": true,
    "confidence_score": 0.95,
    "summary": "…",
    "mitre_tactics": ["Initial Access", "Credential Access"],
    "incidents": [
      {
        "incident_id": "INC-001",
        "severity": "CRITICAL",
        "root_cause": "…",
        "affected_assets": ["host-or-ip", "user"],
        "attack_chain": ["Шаг 1: …", "Шаг 2: …"]
      }
    ]
  },
  "infrastructure_recommendations": [
    {
      "target": "Network / Firewall",
      "priority": "IMMEDIATE",
      "action_type": "CONTAINMENT",
      "recommendation": "…",
      "commands_or_config": "…"
    }
  ]
}

Если атаки нет — attack_detected=false, incidents может быть пустым или содержать
шумный кластер с severity LOW/MEDIUM, recommendations — hardening/detection.
severity инцидента: LOW | MEDIUM | HIGH | CRITICAL (UPPERCASE).
priority: IMMEDIATE | HIGH | MEDIUM | HARDENING.
action_type: CONTAINMENT | PREVENTION | DETECTION | ERADICATION | RECOVERY.
"""


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class SocAIError(Exception):
    """Base error for the SOC AI analyzer."""


class SocAIConfigError(SocAIError):
    """Missing or invalid GigaChat configuration."""


class SocAIAuthError(SocAIError):
    """GigaChat rejected the credentials / scope."""


class SocAITimeoutError(SocAIError):
    """The GigaChat request timed out."""


class SocAIResponseError(SocAIError):
    """The model returned unusable / non-schema JSON."""


# --------------------------------------------------------------------------- #
# Domain models
# --------------------------------------------------------------------------- #
class AlertSeverity(StrEnum):
    """Normalized severity used on inbound alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class IncidentSeverity(StrEnum):
    """Severity labels expected in GigaChat incident objects."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendationPriority(StrEnum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    HARDENING = "HARDENING"


class RecommendationActionType(StrEnum):
    CONTAINMENT = "CONTAINMENT"
    PREVENTION = "PREVENTION"
    DETECTION = "DETECTION"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"


class SOCEvent(BaseModel):
    """One security alert fed into the analyzer."""

    model_config = {"extra": "ignore"}

    seq: int | None = Field(default=None, description="Store sequence number.")
    alert_id: str | None = None
    timestamp: datetime | str | None = None
    rule_id: str | None = None
    rule_level: int | None = Field(default=None, ge=0, le=15)
    rule_description: str | None = None
    severity: AlertSeverity = AlertSeverity.UNKNOWN
    src_ip: str | None = None
    dst_ip: str | None = None
    user_name: str | None = None
    service: str | None = None
    agent_name: str | None = None
    message: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    triage_status: str | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Any:
        if value is None or value == "":
            return AlertSeverity.UNKNOWN
        if isinstance(value, str):
            return value.lower()
        return value

    @classmethod
    def from_any(cls, payload: dict[str, Any] | "SOCEvent") -> "SOCEvent":
        """Build from a dict, flattening nested ``triage`` if present."""
        if isinstance(payload, SOCEvent):
            return payload
        data = dict(payload)
        triage = data.get("triage")
        if isinstance(triage, dict) and "triage_status" not in data:
            data["triage_status"] = triage.get("status")
        return cls.model_validate(data)


class CorrelatedIncident(BaseModel):
    """One correlated incident reconstructed by the model."""

    incident_id: str = Field(..., min_length=1)
    severity: IncidentSeverity
    root_cause: str = Field(..., min_length=1)
    affected_assets: list[str] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().upper()
        return value


class CorrelationAnalysis(BaseModel):
    """Correlation block of the GigaChat SOC response."""

    attack_detected: bool
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., min_length=1)
    mitre_tactics: list[str] = Field(default_factory=list)
    incidents: list[CorrelatedIncident] = Field(default_factory=list)


class InfrastructureRecommendation(BaseModel):
    """Actionable infrastructure guidance from the model."""

    target: str = Field(..., min_length=1)
    priority: RecommendationPriority
    action_type: RecommendationActionType
    recommendation: str = Field(..., min_length=1)
    commands_or_config: str = Field(default="")

    @field_validator("priority", mode="before")
    @classmethod
    def _coerce_priority(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().upper()
        return value

    @field_validator("action_type", mode="before")
    @classmethod
    def _coerce_action(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().upper()
        return value


class SOCAnalysisPayload(BaseModel):
    """Strict JSON body expected from GigaChat (no NekoWatch metadata)."""

    correlation_analysis: CorrelationAnalysis
    infrastructure_recommendations: list[InfrastructureRecommendation] = Field(
        default_factory=list
    )


class SOCAnalysisResponse(SOCAnalysisPayload):
    """Structured SOC assessment produced by GigaChat (+ local metadata)."""

    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC-время завершения анализа.",
    )
    model_name: str | None = Field(
        default=None,
        description="Какая модель GigaChat дала ответ.",
    )
    events_analyzed: int = Field(
        default=0,
        ge=0,
        description="Сколько событий ушло в промпт.",
    )


# --------------------------------------------------------------------------- #
# Client helpers
# --------------------------------------------------------------------------- #
def _hydrate_env_from_dotenv() -> None:
    """Load ``GIGACHAT_*`` keys from a local ``.env`` if not already exported."""
    env_path = _PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return
    try:
        raw = env_path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.lower().startswith("export "):
            key = key[7:].strip()
        if not key.startswith("GIGACHAT_"):
            continue
        # Empty / whitespace env placeholders must not block .env
        if (os.getenv(key) or "").strip():
            continue
        value = value.strip().strip("'").strip('"')
        if value:
            os.environ[key] = value


def _normalize_credentials(raw: str) -> str:
    """Strip quotes/prefixes; Base64-encode ``client_id:secret`` if needed."""
    import base64
    import binascii

    value = (raw or "").strip().strip("'").strip('"')
    # People often paste "Basic <key>" from curl examples
    if value.lower().startswith("basic "):
        value = value[6:].strip()
    # Collapse accidental whitespace / newlines from copy-paste
    value = "".join(value.split())
    if not value:
        return value

    # Already valid Base64 payload → keep as-is
    try:
        padded = value + ("=" * (-len(value) % 4))
        base64.b64decode(padded, validate=True)
        return value
    except (binascii.Error, ValueError):
        pass

    # Raw client_id:client_secret → encode like GigaChat console key
    if ":" in value:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    return value


def _load_credentials() -> tuple[str, str]:
    """Read auth material from the environment / project ``.env``."""
    _hydrate_env_from_dotenv()
    credentials = _normalize_credentials(os.getenv("GIGACHAT_CREDENTIALS") or "")
    scope = (os.getenv("GIGACHAT_SCOPE") or "GIGACHAT_API_PERS").strip()
    if not credentials:
        raise SocAIConfigError(
            "GIGACHAT_CREDENTIALS is not set. Put it in .env or export "
            "GIGACHAT_CREDENTIALS / GIGACHAT_SCOPE from the GigaChat developer console."
        )
    # Keep normalized value for subsequent client builds
    os.environ["GIGACHAT_CREDENTIALS"] = credentials
    return credentials, scope


def _build_client(
    *,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any:
    """Construct a :class:`gigachat.GigaChat` client from env credentials."""
    try:
        from gigachat import GigaChat
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise SocAIConfigError(
            "Package 'gigachat' is not installed. "
            "Run: pip install 'gigachat>=0.2.0'"
        ) from exc

    credentials, scope = _load_credentials()
    # GigaChat corporate endpoints often sit behind a private CA; default off
    # unless GIGACHAT_VERIFY_SSL_CERTS is explicitly enabled.
    verify_raw = (os.getenv("GIGACHAT_VERIFY_SSL_CERTS") or "false").strip().lower()
    verify_ssl = verify_raw in {"1", "true", "yes", "on"}
    return GigaChat(
        credentials=credentials,
        scope=scope,
        model=model,
        timeout=timeout,
        verify_ssl_certs=verify_ssl,
        ca_bundle_file=os.getenv("GIGACHAT_CA_BUNDLE_FILE") or None,
    )


# One shared client for the whole process — library keeps/refreshes OAuth token.
_giga_client: Any | None = None
_giga_lock: asyncio.Lock | None = None


def _get_giga_lock() -> asyncio.Lock:
    global _giga_lock
    if _giga_lock is None:
        _giga_lock = asyncio.Lock()
    return _giga_lock


async def get_shared_gigachat(
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any:
    """Return the process-wide GigaChat client (lazy singleton).

    Creating a new ``GigaChat()`` per request forces a fresh OAuth round-trip
    and can hit Sber rate limits. Keep one instance so the SDK reuses the
    access token and only refreshes it when it expires (~30 minutes).
    """
    global _giga_client
    async with _get_giga_lock():
        if _giga_client is None:
            _giga_client = _build_client(model=DEFAULT_MODEL, timeout=timeout)
            logger.info("gigachat_client_initialized")
        return _giga_client


async def close_shared_gigachat() -> None:
    """Close the shared client (call from app lifespan shutdown)."""
    global _giga_client
    async with _get_giga_lock():
        client = _giga_client
        _giga_client = None
    if client is None:
        return
    try:
        await client.aclose()
        logger.info("gigachat_client_closed")
    except Exception:  # noqa: BLE001 - shutdown must not raise
        logger.exception("gigachat_client_close_failed")


def _normalize_events(
    events: Sequence[dict[str, Any] | SOCEvent],
) -> list[SOCEvent]:
    """Validate and cap the inbound batch."""
    if not events:
        raise SocAIError("events list is empty — nothing to analyze")

    normalized: list[SOCEvent] = []
    errors: list[str] = []
    for index, item in enumerate(events[:MAX_EVENTS_PER_REQUEST]):
        try:
            normalized.append(SOCEvent.from_any(item))  # type: ignore[arg-type]
        except ValidationError as exc:
            errors.append(f"events[{index}]: {exc.errors(include_url=False)}")

    if not normalized:
        raise SocAIError(
            "no valid events after validation: " + "; ".join(errors[:3])
        )
    if errors:
        logger.warning(
            "skipped_invalid_events",
            extra={"count": len(errors), "sample": errors[0]},
        )
    return normalized


def _events_as_prompt_payload(events: Sequence[SOCEvent]) -> str:
    """Serialize the batch to compact JSON for the user message."""
    payload = [
        event.model_dump(mode="json", exclude_none=True) for event in events
    ]
    return json.dumps(
        {
            "event_count": len(payload),
            "events": payload,
        },
        ensure_ascii=False,
        indent=2,
    )


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a possibly noisy model reply."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise SocAIResponseError("model reply contains no JSON object")
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise SocAIResponseError(f"invalid JSON from model: {exc}") from exc
    if not isinstance(data, dict):
        raise SocAIResponseError("JSON root must be an object")
    return data


def _map_transport_error(exc: BaseException) -> SocAIError:
    """Translate gigachat/httpx exceptions into SocAI* errors."""
    from gigachat.exceptions import AuthenticationError, ResponseError

    try:
        import httpx
    except ImportError:  # pragma: no cover
        httpx = None  # type: ignore[assignment]

    if isinstance(exc, AuthenticationError):
        return SocAIAuthError(
            "GigaChat authentication failed — check GIGACHAT_CREDENTIALS "
            f"and GIGACHAT_SCOPE. Detail: {exc}"
        )
    if httpx is not None and isinstance(exc, httpx.TimeoutException):
        return SocAITimeoutError(f"GigaChat request timed out: {exc}")
    msg = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in msg or "SSLCertVerificationError" in type(exc).__name__:
        return SocAIConfigError(
            "GigaChat SSL verification failed. Set GIGACHAT_VERIFY_SSL_CERTS=false "
            "or provide GIGACHAT_CA_BUNDLE_FILE. Detail: "
            f"{exc}"
        )
    if isinstance(exc, ResponseError):
        status = getattr(exc, "status_code", None)
        if status == 401:
            return SocAIAuthError(str(exc))
        return SocAIResponseError(f"GigaChat API error ({status}): {exc}")
    return SocAIError(f"GigaChat request failed: {exc}")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
async def analyze_security_events(
    events: list[dict],
    *,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT,
    use_max_fallback: bool = True,
) -> SOCAnalysisResponse:
    """Ask GigaChat to assess a batch of SOC alerts.

    Returns a validated :class:`SOCAnalysisResponse` with
    ``correlation_analysis`` and ``infrastructure_recommendations``.
    """
    from gigachat.models import Chat, Messages, MessagesRole

    normalized = _normalize_events(events)
    user_payload = _events_as_prompt_payload(normalized)
    chat = Chat(
        messages=[
            Messages(role=MessagesRole.SYSTEM, content=_SYSTEM_PROMPT),
            Messages(
                role=MessagesRole.USER,
                content=(
                    "Проанализируй следующий пакет security-событий и верни "
                    "JSON строго по схеме correlation_analysis + "
                    "infrastructure_recommendations.\n\n"
                    f"{user_payload}"
                ),
            ),
        ],
        temperature=0.1,
        max_tokens=4096,
    )

    models_to_try = [model]
    if use_max_fallback and model != FALLBACK_MODEL:
        models_to_try.append(FALLBACK_MODEL)

    last_error: Exception | None = None
    for attempt_model in models_to_try:
        try:
            analysis = await _call_gigachat(chat, model=attempt_model, timeout=timeout)
            analysis.model_name = attempt_model
            analysis.events_analyzed = len(normalized)
            analysis.analyzed_at = datetime.now(timezone.utc)
            return analysis
        except (SocAIAuthError, SocAIConfigError, SocAITimeoutError):
            raise
        except (SocAIResponseError, SocAIError, ValidationError) as exc:
            last_error = exc
            logger.warning(
                "soc_ai_attempt_failed",
                extra={"model": attempt_model, "error": str(exc)},
            )
            continue

    assert last_error is not None
    if isinstance(last_error, SocAIError):
        raise last_error
    raise SocAIResponseError(str(last_error)) from last_error


async def _call_gigachat(
    chat: Any,
    *,
    model: str,
    timeout: float,
) -> SOCAnalysisResponse:
    """One model attempt: prefer ``achat_parse``, fall back to JSON extract."""
    from gigachat.exceptions import LengthFinishReasonError

    chat.model = model
    giga = await get_shared_gigachat(timeout=timeout)

    try:
        try:
            _completion, parsed = await giga.achat_parse(
                chat,
                response_format=SOCAnalysisPayload,
                strict=True,
            )
            return SOCAnalysisResponse.model_validate(parsed.model_dump())
        except LengthFinishReasonError as exc:
            raise SocAIResponseError(
                "GigaChat truncated the structured response "
                "(finish_reason=length)"
            ) from exc
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
            logger.info(
                "achat_parse_fallback",
                extra={"reason": type(exc).__name__, "model": model},
            )
            completion = await giga.achat(chat)
    except SocAIError:
        raise
    except Exception as exc:  # noqa: BLE001 - transport / auth
        raise _map_transport_error(exc) from exc

    try:
        content = completion.choices[0].message.content or ""
    except (AttributeError, IndexError, TypeError) as exc:
        raise SocAIResponseError(
            "GigaChat response has no assistant content"
        ) from exc

    try:
        data = _extract_json_object(content)
        payload = SOCAnalysisPayload.model_validate(data)
        return SOCAnalysisResponse.model_validate(payload.model_dump())
    except ValidationError as exc:
        raise SocAIResponseError(
            "model JSON failed schema validation: "
            f"{exc.errors(include_url=False, include_context=False)}"
        ) from exc


__all__ = [
    "AlertSeverity",
    "IncidentSeverity",
    "RecommendationPriority",
    "RecommendationActionType",
    "SOCEvent",
    "CorrelatedIncident",
    "CorrelationAnalysis",
    "InfrastructureRecommendation",
    "SOCAnalysisPayload",
    "SOCAnalysisResponse",
    "SocAIError",
    "SocAIConfigError",
    "SocAIAuthError",
    "SocAITimeoutError",
    "SocAIResponseError",
    "analyze_security_events",
    "get_shared_gigachat",
    "close_shared_gigachat",
    "DEFAULT_MODEL",
    "FALLBACK_MODEL",
]
