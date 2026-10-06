"""Server-rendered pages (Jinja2)."""

from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from core import mitre
from core.config import get_settings
from domain.models import Severity, TriageStatus
from domain.queries import TimelineInterval

router = APIRouter(tags=["pages"], include_in_schema=False)


@lru_cache(maxsize=1)
def _templates() -> Jinja2Templates:
    """Jinja2 environment rooted at ``templates/``."""
    return Jinja2Templates(directory=str(get_settings().templates_dir))


def _base_context(request: Request) -> dict[str, object]:
    """Context every page needs: filter vocabularies and app identity."""
    settings = get_settings()
    return {
        "request": request,
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "log_file": str(settings.log_file),
        "severities": [s.value for s in Severity],
        "triage_statuses": [s.value for s in TriageStatus],
        "intervals": [i.value for i in TimelineInterval],
        "tactics": mitre.tactic_catalog(),
        "techniques": mitre.catalog(),
    }


@router.get("/", response_class=HTMLResponse, summary="SOC dashboard")
async def dashboard(request: Request) -> HTMLResponse:
    """The analyst dashboard: charts, live feed, search, triage and export."""
    return _templates().TemplateResponse(
        request, "index.html", _base_context(request)
    )


@router.get("/logener", response_class=HTMLResponse, summary="Generator control")
async def logener_page(request: Request) -> HTMLResponse:
    """Start/stop the Logener alert generator and watch its throughput."""
    return _templates().TemplateResponse(
        request, "logener.html", _base_context(request)
    )


@router.get("/api", response_class=HTMLResponse, summary="External API connect")
async def api_page(request: Request) -> HTMLResponse:
    """Connect an external HTTP/Wazuh API as a live alert source."""
    return _templates().TemplateResponse(
        request, "api.html", _base_context(request)
    )
