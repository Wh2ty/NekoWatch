"""Declarative ORM models (SQLAlchemy 2.0).

Tables mirror the previous raw-SQLite schema so existing databases continue
to work after the migration. Indices on timestamp, severity, source IP,
rule id and triage status keep dashboard and search queries index-backed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Alert(Base):
    """Normalized security alert — one row per ingested Logener/Wazuh event."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("idx_alerts_ts", "ts_epoch"),
        Index("idx_alerts_rule", "rule_id"),
        Index("idx_alerts_level", "rule_level"),
        Index("idx_alerts_sev_ts", "severity", "ts_epoch"),
        Index("idx_alerts_src", "src_ip"),
        Index("idx_alerts_dst", "dst_ip"),
        Index("idx_alerts_user", "user_name"),
        Index("idx_alerts_service", "service"),
        Index("idx_alerts_triage", "triage_status"),
        Index("idx_alerts_loglevel", "log_level"),
        Index("idx_alerts_alertid", "alert_id"),
    )

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    alert_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ts: Mapped[str] = mapped_column(String(64), nullable=False)
    ts_epoch: Mapped[float] = mapped_column(Float, nullable=False)

    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    rule_level: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_groups: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rule_firedtimes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_mail: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")

    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    agent_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    manager_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    decoder_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    program_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    log_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    amount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    currency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    recipient: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prev_country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failed_attempts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    window_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expected_balance: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    actual_balance: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    mitre_tactics: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    triage_status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")
    triage_analyst: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    triage_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    triage_updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    mitre_rows: Mapped[list["AlertMitre"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    triage_history: Mapped[list["TriageEventRow"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        lazy="noload",
    )


class AlertMitre(Base):
    """ATT&CK tactic/technique mapping for one alert (side table)."""

    __tablename__ = "alert_mitre"
    __table_args__ = (
        PrimaryKeyConstraint("seq", "technique_id"),
        Index("idx_mitre_tactic", "tactic_id"),
        Index("idx_mitre_tech", "technique_id"),
    )

    seq: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.seq", ondelete="CASCADE"), nullable=False
    )
    tactic_id: Mapped[str] = mapped_column(String(32), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False)

    alert: Mapped["Alert"] = relationship(back_populates="mitre_rows")


class TriageEventRow(Base):
    """Immutable audit entry for a triage state transition."""

    __tablename__ = "triage_events"
    __table_args__ = (Index("idx_triage_seq", "seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.seq", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    analyst: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    alert: Mapped["Alert"] = relationship(back_populates="triage_history")


class IngestState(Base):
    """Byte-offset checkpoint so the tail resumes after a restart."""

    __tablename__ = "ingest_state"

    path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    inode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    byte_offset: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class CorrelationIncident(Base):
    """Persisted correlation finding (e.g. a brute-force burst).

    Correlation itself is computed on demand; this table is the durable trail
    when a detector chooses to record an incident for later review.
    """

    __tablename__ = "correlation_incidents"
    __table_args__ = (
        Index("idx_corr_src", "src_ip"),
        Index("idx_corr_kind_ts", "kind", "first_seen"),
        UniqueConstraint(
            "kind", "src_ip", "user_name", "first_seen", name="uq_corr_signature"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, default="brute_force")
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_seen: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    unique_users: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_level: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    sample_seqs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


# --------------------------------------------------------------------------- #
# Status monitoring: sources + LAN users
# --------------------------------------------------------------------------- #
class MonitoredSource(Base):
    """Log source (typically a Wazuh agent) with event + network health."""

    __tablename__ = "monitored_sources"
    __table_args__ = (
        Index("idx_msrc_status", "event_status"),
        Index("idx_msrc_last_seen", "last_event_at"),
        UniqueConstraint("agent_id", name="uq_msrc_agent_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # own = registered asset; foreign = unseen / untrusted
    registration: Mapped[str] = mapped_column(String(16), nullable=False, default="own")
    # healthy | problematic  (event inactivity timeout)
    event_status: Mapped[str] = mapped_column(String(16), nullable=False, default="healthy")
    # connected | disconnected  (ICMP ping of ip_address)
    network_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="disconnected"
    )
    last_event_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_ping_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_event_seq: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class NetworkUser(Base):
    """LAN workstation / analyst host tracked by ICMP ping."""

    __tablename__ = "network_users"
    __table_args__ = (
        Index("idx_nuser_net", "network_status"),
        UniqueConstraint("username", name="uq_nuser_username"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    registration: Mapped[str] = mapped_column(String(16), nullable=False, default="own")
    network_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="disconnected"
    )
    last_ping_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_rtt_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class StatusNotification(Base):
    """In-app alert for analysts (e.g. source went problematic)."""

    __tablename__ = "status_notifications"
    __table_args__ = (Index("idx_snotif_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("monitored_sources.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


class CorrelationRule(Base):
    """User-defined streaming correlation rule evaluated on ingest."""

    __tablename__ = "correlation_rules"
    __table_args__ = (
        Index("idx_crule_enabled", "enabled"),
        UniqueConstraint("name", name="uq_crule_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    field: Mapped[str] = mapped_column(String(64), nullable=False)
    operator: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    group_by: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_fired_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
