"""SQLAlchemy ORM models for the Phase 1 foundation.

Enumerated states are stored as stable uppercase strings exactly as written in
the PRD (section 31).
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # ADMINISTRATOR | SCANNER
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))

    assignments: Mapped[list["Assignment"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", foreign_keys="Assignment.user_id"
    )


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    user: Mapped[User] = relationship()


class PrivateCidr(Base):
    __tablename__ = "private_cidrs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cidr: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    note: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))


class DenyRule(Base):
    __tablename__ = "deny_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # DOMAIN_EXACT | DOMAIN_SUFFIX | IP | CIDR
    rule_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    # GOVERNMENT | MILITARY | HEALTHCARE | CUSTOM
    category: Mapped[str] = mapped_column(String(16), nullable=False, default="CUSTOM")
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))

    __table_args__ = (UniqueConstraint("rule_type", "value", name="uq_deny_rule"),)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # IPV4 | CIDR | DOMAIN
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    note: Mapped[str] = mapped_column(String(512), default="")

    # Public-target attestation record (PRD 6.2).
    attestation_checkbox: Mapped[bool] = mapped_column(Boolean, default=False)
    attestation_text: Mapped[str | None] = mapped_column(Text)
    attested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    attested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))

    __table_args__ = (UniqueConstraint("kind", "value", name="uq_target_value"),)

    assignments: Mapped[list["Assignment"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Assignment(Base):
    __tablename__ = "assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))

    __table_args__ = (UniqueConstraint("target_id", "user_id", name="uq_assignment"),)

    target: Mapped[Target] = relationship(back_populates="assignments")
    user: Mapped[User] = relationship(back_populates="assignments", foreign_keys=[user_id])


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    # IP | HOSTNAME
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="fake")
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    # Discovered assets never inherit authorization (PRD 6.2 / SCOPE-04).
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("target_id", "kind", "value", name="uq_asset"),)

    target: Mapped[Target] = relationship(back_populates="assets")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    read_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    # PASSIVE | SAFE_ACTIVE | STANDARD_ACTIVE
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    classification: Mapped[str] = mapped_column(String(8), nullable=False)  # PASSIVE | ACTIVE
    # INTERVAL | DAILY
    recurrence: Mapped[str] = mapped_column(String(12), nullable=False)
    interval_minutes: Mapped[int | None] = mapped_column(Integer)
    at_time: Mapped[str | None] = mapped_column(String(5))  # "HH:MM" for DAILY
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    overlap_policy: Mapped[str] = mapped_column(String(8), default="SKIP")  # SKIP | ALLOW
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    # Hash of the frozen attestation-relevant fields; changing them invalidates
    # a stored active attestation (PRD 8.2).
    options_hash: Mapped[str] = mapped_column(String(64), default="")
    attestation_text: Mapped[str | None] = mapped_column(Text)
    attested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    attested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    target: Mapped[Target] = relationship()


class ScanExecution(Base):
    __tablename__ = "scan_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    requested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    schedule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("schedules.id"))
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    classification: Mapped[str] = mapped_column(String(8), nullable=False)  # PASSIVE | ACTIVE
    # One of constants.SCAN_STATES
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT")
    options: Mapped[dict] = mapped_column(JSON, default=dict)

    # Approval linkage (Phase 3).
    approval_id: Mapped[str | None] = mapped_column(String(36))
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    approval_expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    # Lifecycle timestamps.
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    queued_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    runtime_deadline_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancel_reason: Mapped[str | None] = mapped_column(String(256))
    partial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(36), default=_uuid)

    # Reproducibility metadata (SCAN-10).
    stages: Mapped[list] = mapped_column(JSON, default=list)
    tool_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_args: Mapped[dict] = mapped_column(JSON, default=dict)
    parser_version: Mapped[str] = mapped_column(String(16), default="")
    template_set_hash: Mapped[str] = mapped_column(String(64), default="")
    result_dir: Mapped[str | None] = mapped_column(String(512))

    target: Mapped[Target] = relationship()


class ScanApproval(Base):
    __tablename__ = "scan_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_executions.id"), nullable=False
    )
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    requested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    schedule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("schedules.id"))
    occurrence_id: Mapped[str | None] = mapped_column(String(36))
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    attestation_text: Mapped[str] = mapped_column(Text, nullable=False)
    requested_options: Mapped[dict] = mapped_column(JSON, default=dict)
    # Canonical scope decision captured when the request was created (PRD 6.4.8).
    scope_at_request: Mapped[dict] = mapped_column(JSON, default=dict)
    # AWAITING_APPROVAL | APPROVED | DENIED | EXPIRED
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="AWAITING_APPROVAL")
    decided_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    decision_reason: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"))
    execution_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_executions.id"))
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    confidence: Mapped[str] = mapped_column(String(16), default="")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("target_id", "asset_id", "port", "protocol", name="uq_service"),
    )


class EmergencyStop(Base):
    __tablename__ = "emergency_stops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    requested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    requested_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # ALL | SELECTED
    target_scope: Mapped[str] = mapped_column(String(12), nullable=False, default="ALL")
    execution_ids: Mapped[list] = mapped_column(JSON, default=list)
    # REQUESTED | CONFIRMED | FAILED | CLEARED
    state: Mapped[str] = mapped_column(String(12), nullable=False, default="REQUESTED")
    note: Mapped[str] = mapped_column(String(512), default="")
    cleared_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    cleared_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"))
    execution_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_executions.id"))
    # DNS_RECORD | HTTP_HEADER | HTTP_STATUS | TLS | TECH | TITLE | OSINT
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    value: Mapped[str] = mapped_column(Text, default="")
    source_tool: Mapped[str] = mapped_column(String(32), default="")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("target_id", "kind", "key", "value", name="uq_observation"),
    )


class ScheduleOccurrence(Base):
    __tablename__ = "schedule_occurrences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    schedule_id: Mapped[str] = mapped_column(String(36), ForeignKey("schedules.id"), nullable=False)
    scheduled_for: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # PENDING | AWAITING_APPROVAL | RUNNING | COMPLETED | EXPIRED | DENIED | CANCELLED | SKIPPED
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    execution_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_executions.id"))
    note: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("schedule_id", "scheduled_for", name="uq_occurrence"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(96), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(48), default="")
    object_id: Mapped[str] = mapped_column(String(96), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    curr_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
