"""Status monitoring DTOs: sources, LAN users, notifications, status cards."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RegistrationStatus(StrEnum):
    """Whether the asset is known to the SOC inventory."""

    OWN = "own"
    FOREIGN = "foreign"


class EventHealth(StrEnum):
    """Derived from last-event age vs timeout."""

    HEALTHY = "healthy"
    PROBLEMATIC = "problematic"


class NetworkReachability(StrEnum):
    """ICMP ping result."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"


class SourceStatusCard(BaseModel):
    """UI card payload for one monitored source."""

    id: int
    agent_id: str
    name: str | None = None
    ip_address: str | None = None
    registration: RegistrationStatus
    registration_label: str
    event_status: EventHealth
    network_status: NetworkReachability
    # Combined reachability: ping OK and events within timeout.
    connection_ok: bool = False
    connection_label: str
    last_event_at: datetime | None = None
    last_ping_at: datetime | None = None
    seconds_since_event: float | None = None
    timeout_seconds: int = 60
    event_count: int = 0
    is_demo: bool = False


class UserStatusCard(BaseModel):
    """UI card payload for one LAN user."""

    id: int
    username: str
    display_name: str | None = None
    ip_address: str
    registration: RegistrationStatus
    registration_label: str
    network_status: NetworkReachability
    connection_ok: bool = False
    connection_label: str
    last_ping_at: datetime | None = None
    last_rtt_ms: float | None = None
    is_demo: bool = False


class StatusNotificationOut(BaseModel):
    """Analyst-facing notification."""

    id: int
    kind: str
    severity: str
    title: str
    message: str
    source_id: int | None = None
    acknowledged: bool = False
    created_at: datetime


class StatusBoardResponse(BaseModel):
    """Dashboard bundle: source cards, user cards, recent notifications."""

    sources: list[SourceStatusCard]
    users: list[UserStatusCard]
    notifications: list[StatusNotificationOut]
    source_timeout_seconds: int = 60
    generated_at: datetime
    mock: bool = False
    demo: bool = False


class SourceCreateRequest(BaseModel):
    """Register a source in the inventory as an owned asset."""

    agent_id: str = Field(min_length=1, max_length=64)
    name: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    registration: RegistrationStatus = RegistrationStatus.OWN
    timeout_seconds: int = Field(default=60, ge=10, le=3600)


class NetworkUserCreateRequest(BaseModel):
    """Register a LAN user for ping monitoring."""

    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=128)
    ip_address: str = Field(min_length=7, max_length=64)
    registration: RegistrationStatus = RegistrationStatus.OWN
