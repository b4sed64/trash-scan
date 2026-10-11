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
    Float,
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


class PortSet(Base):
    """A reusable, administrator-defined named set of ports for active scans.

    ``protocol`` is TCP or UDP — a set is one or the other, never mixed, matching
    how Nmap's own combined port spec (``-p T:...,U:...``) keeps the two apart.
    A UDP set is only usable by the Standard active profile with UDP scanning
    enabled (PRD §12.1); it replaces the fixed ``TRASHSCAN_STANDARD_UDP_PORTS``
    default for that scan when chosen.
    """

    __tablename__ = "port_sets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    protocol: Mapped[str] = mapped_column(String(3), nullable=False, default="TCP")
    spec: Mapped[str] = mapped_column(String(2000), nullable=False)
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
    # A scan may cover several targets; each target is one execution sharing a
    # group id. A single-target scan is a group of one.
    scan_group_id: Mapped[str | None] = mapped_column(String(36), index=True)
    group_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    group_size: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
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
    # One approval covers the whole scan (all its per-target executions).
    scan_group_id: Mapped[str | None] = mapped_column(String(36), index=True)
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


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"))
    service_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("services.id"))
    # Stable identity (PRD §15.2): does not change on volatile evidence.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(32), nullable=False, default="nuclei")
    rule_id: Mapped[str] = mapped_column(String(160), nullable=False)
    template_hash: Mapped[str] = mapped_column(String(64), default="")
    # INFO | LOW | MEDIUM | HIGH | CRITICAL
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="INFO")
    name: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    asset_value: Mapped[str] = mapped_column(String(256), default="")
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    matcher_name: Mapped[str] = mapped_column(String(128), default="")
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    # OBSERVED (seen in the most recent compatible scan) | NOT_OBSERVED
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OBSERVED")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    first_execution_id: Mapped[str | None] = mapped_column(String(36))
    last_execution_id: Mapped[str | None] = mapped_column(String(36))

    __table_args__ = (UniqueConstraint("target_id", "fingerprint", name="uq_finding"),)


class FindingSighting(Base):
    __tablename__ = "finding_sightings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_executions.id"), nullable=False
    )
    severity: Mapped[str] = mapped_column(String(10), default="INFO")
    evidence_key: Mapped[str] = mapped_column(String(200), default="")
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("finding_id", "execution_id", name="uq_finding_sighting"),
    )


class ScanComparison(Base):
    __tablename__ = "scan_comparisons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_executions.id"), nullable=False
    )
    baseline_execution_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_executions.id")
    )
    eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("execution_id", name="uq_comparison_execution"),)


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


class CoverageEntry(Base):
    """Per-execution, per-check-family coverage record (PRD v2 §7, Phase 8).

    Records whether a check family was actually assessed, so a "no findings"
    result can be told apart from "we could not check". Written once at
    normalization and never updated (append-only / immutable by convention):
    a scan's coverage is a historical fact about that run.

    ``outcome`` is one of: ASSESSED (ran to completion, a clean result is a real
    negative), COMPLETED_WITH_GAPS (ran but hit a limit — timeout, truncation,
    budget), NOT_ASSESSED (did not run — tool missing, nothing in scope, skipped),
    INCONCLUSIVE (ran but completion could not be confirmed). Only ASSESSED may
    establish NOT_OBSERVED in comparison.
    """

    __tablename__ = "coverage_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_executions.id"), nullable=False, index=True
    )
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    check_family: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), default="")
    # Bounded, redacted pointer to where the evidence lives (e.g. a raw-output
    # file basename) — never the raw payload itself.
    evidence_ref: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("execution_id", "stage", "check_family", name="uq_coverage_entry"),
    )


class Issue(Base):
    """A canonical issue identity (PRD v2 §10, Phase 9).

    Sits above :class:`Finding`: several findings — possibly from different tools
    that detect the *same* condition (e.g. httpx ``-tls-grab`` and nmap
    ``ssl-cert`` both reporting an expired certificate) — roll up into one Issue
    per (target, issue_type). Equivalence is declared explicitly in
    ``services/issues.py``; it never merges detectors that are not declared
    equivalent. The underlying Finding/FindingSighting rows are untouched, so the
    canonical layer is a lossless, reversible projection of them.
    """

    __tablename__ = "issues"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    # Canonical equivalence-class key, e.g. "tls:tls-cert-expired" or
    # "nuclei:trashscan-git-config-exposure" (tool-qualified when not shared).
    issue_type: Mapped[str] = mapped_column(String(192), nullable=False)
    category: Mapped[str] = mapped_column(String(48), default="")
    title: Mapped[str] = mapped_column(String(256), default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="INFO")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OBSERVED")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Review / remediation (PRD v2 §12) — three independent dimensions.
    # Analyst validation: UNREVIEWED | VALIDATED | FALSE_POSITIVE | INCONCLUSIVE
    validation_state: Mapped[str] = mapped_column(String(16), nullable=False, default="UNREVIEWED")
    # Remediation workflow: OPEN | IN_PROGRESS | MITIGATED | RESOLVED_VERIFIED | RISK_ACCEPTED
    remediation_state: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    owner: Mapped[str] = mapped_column(String(128), default="")
    due_date: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    desired_state: Mapped[str] = mapped_column(String(256), default="")
    remediation_plan: Mapped[str] = mapped_column(Text, default="")
    # Set when a previously RESOLVED_VERIFIED issue is observed again (§12.3.6);
    # prior closure metadata and ownership are preserved.
    reopened: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    closed_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    closure_reason: Mapped[str] = mapped_column(String(512), default="")
    closure_evidence_ref: Mapped[str] = mapped_column(String(256), default="")
    verification_method: Mapped[str] = mapped_column(String(24), default="")  # RETEST_NEGATIVE | MANUAL
    manually_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint("target_id", "issue_type", name="uq_issue"),
    )


class RiskException(Base):
    """An administrator-accepted risk on an issue (PRD v2 §12.1). Requires a
    reason, affected scope, optional compensating controls, and an expiry/review
    date. Accepted-risk issues stay in history and exports; overdue exceptions
    become visible for renewed review."""

    __tablename__ = "risk_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    issue_id: Mapped[str] = mapped_column(String(36), ForeignKey("issues.id"), nullable=False,
                                          index=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    scope: Mapped[str] = mapped_column(String(256), default="")
    compensating_controls: Mapped[str] = mapped_column(String(512), default="")
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ExploitabilityAssessment(Base):
    """Offline exploitability assessment of an issue against a reviewed module
    (PRD v2 §21, Phase 13). Purely analytical — no target contact and no
    execution. It records, per prerequisite, whether evidence is SATISFIED /
    MISSING / CONTRADICTED / UNKNOWN / STALE, and derives an eligibility of
    NEEDS_EVIDENCE / INCOMPATIBLE / BLOCKED_POLICY / ELIGIBLE_FOR_PROOF.
    ELIGIBLE_FOR_PROOF means a plan *may be requested*, never that execution is
    authorized or succeeded — active capabilities stay behind their own flags,
    approvals and real-lab gates.
    """

    __tablename__ = "exploitability_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False,
                                           index=True)
    issue_id: Mapped[str] = mapped_column(String(36), ForeignKey("issues.id"), nullable=False,
                                          index=True)
    module_id: Mapped[str] = mapped_column(String(128), nullable=False)
    module_admission_state: Mapped[str] = mapped_column(String(16), default="")
    # NEEDS_EVIDENCE | INCOMPATIBLE | BLOCKED_POLICY | ELIGIBLE_FOR_PROOF
    eligibility: Mapped[str] = mapped_column(String(20), nullable=False, default="NEEDS_EVIDENCE")
    prerequisites: Mapped[list] = mapped_column(JSON, default=list)
    expected_effect: Mapped[str] = mapped_column(String(512), default="")
    next_action: Mapped[str] = mapped_column(String(256), default="")
    freshness_deadline: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    assessment_version: Mapped[str] = mapped_column(String(16), default="")
    assessed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("issue_id", "module_id", name="uq_exploitability_assessment"),
    )


class LabEnvironment(Base):
    """A registered, isolated lab environment (PRD v2 §21.6, Phase 15). Isolation
    must be *proven* (target-only egress, blocked control-plane/internet/other
    targets) before any active capability runs — `isolation_verified` stays False
    until that proof is recorded; private addressing alone is never sufficient."""

    __tablename__ = "lab_environments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), default="fake")
    egress_policy: Mapped[str] = mapped_column(String(512), default="")
    isolation_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    isolation_proof_ref: Mapped[str] = mapped_column(String(256), default="")
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LabFixture(Base):
    """A disposable lab fixture bound to a target, with a recoverable baseline
    (PRD v2 §21.6). A snapshot alone is insufficient — a successful restore
    rehearsal and HEALTHY baseline must be recorded before the fixture is
    proof-ready. Holds an exclusive lock while an attempt uses it."""

    __tablename__ = "lab_fixtures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    lab_environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("lab_environments.id"), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="")
    build_id: Mapped[str] = mapped_column(String(128), default="")
    snapshot_id: Mapped[str] = mapped_column(String(128), default="")
    snapshot_digest: Mapped[str] = mapped_column(String(128), default="")
    # HEALTHY | DEGRADED | UNKNOWN | RECOVERY_REQUIRED | RECOVERY_FAILED
    baseline_health: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    restore_rehearsed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    restore_rehearsal_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    locked_by: Mapped[str | None] = mapped_column(String(64))
    locked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("target_id", name="uq_lab_fixture_target"),)


class RecoveryRecord(Base):
    """A recovery/cleanup record for a fixture (PRD v2 §21.6/§21.7). Recovery
    outcome is tracked independently of any proof outcome and may outlive an
    attempt; a RECOVERY_FAILED blocks further active work on the fixture until an
    administrator verifies readiness."""

    __tablename__ = "recovery_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    fixture_id: Mapped[str] = mapped_column(String(36), ForeignKey("lab_fixtures.id"),
                                            nullable=False, index=True)
    # NOT_NEEDED | PENDING | VERIFIED_CLEAN | RESTORED_VERIFIED | RECOVERY_FAILED
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    detail: Mapped[str] = mapped_column(String(512), default="")
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProofPlan(Base):
    """An immutable one-shot proof plan (PRD v2 §21.5/§21.7, Phase 16). Binds the
    exact fixture, module/action + options, a per-attempt marker, the evaluator,
    budgets and recovery steps into a hashed, approved unit. Changing any bound
    field requires a new plan + approval. Approval authorizes exactly one start
    within a two-hour window; it never bypasses the lab-proof flag or fixture
    readiness gates checked at execution."""

    __tablename__ = "proof_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    fixture_id: Mapped[str] = mapped_column(String(36), ForeignKey("lab_fixtures.id"), nullable=False)
    issue_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("issues.id"))
    module_id: Mapped[str] = mapped_column(String(128), nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    proof_marker: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluator: Mapped[str] = mapped_column(String(32), default="marker-echo")
    budgets: Mapped[dict] = mapped_column(JSON, default=dict)
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    engagement_ref: Mapped[str] = mapped_column(String(256), default="")
    attestation_text: Mapped[str] = mapped_column(Text, default="")
    operator_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    # DRAFT | AWAITING_APPROVAL | APPROVED | CONSUMED | DENIED | EXPIRED
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT")
    approved_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProofAttempt(Base):
    """One execution of a proof plan (PRD v2 §21.7). Lifecycle state and the
    proof/recovery outcomes are independent dimensions; a successful proof with
    failed recovery is both a demonstrated proof and an unresolved recovery
    incident. No retry is hidden within an attempt."""

    __tablename__ = "proof_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("proof_plans.id"), nullable=False,
                                         index=True)
    # QUEUED|PREFLIGHT|RUNNING|STOPPING|RECOVERING|COMPLETED|FAILED|BLOCKED|TIMED_OUT|CANCELLED
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED")
    # DEMONSTRATED|ATTEMPTED_NOT_DEMONSTRATED|INCONCLUSIVE|BLOCKED|ERROR
    proof_outcome: Mapped[str | None] = mapped_column(String(28))
    # NOT_NEEDED|PENDING|VERIFIED_CLEAN|RESTORED_VERIFIED|RECOVERY_FAILED
    recovery_outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="NOT_NEEDED")
    blocked_reason: Mapped[str] = mapped_column(String(512), default="")
    measured_runtime_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProofEvidence(Base):
    """Bounded, nonce-correlated evidence for a proof attempt (PRD v2 §21.7).
    DEMONSTRATED requires the per-attempt marker to be echoed and a negative
    control to hold — the framework merely reporting success is insufficient."""

    __tablename__ = "proof_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    attempt_id: Mapped[str] = mapped_column(String(36), ForeignKey("proof_attempts.id"),
                                            nullable=False, index=True)
    marker: Mapped[str] = mapped_column(String(64), default="")
    demonstrated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    native_code: Mapped[str] = mapped_column(String(32), default="")
    negative_control_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redacted_summary: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class StreamEvent(Base):
    """A durable, ordered status/output/evidence event for the live execution
    workspace (PRD v2 §22.6, Phase 17). Status is database truth; output events
    never overwrite it. Output payloads are sanitized (ANSI/control stripped,
    HTML-escaped) at write time — the terminal renderer is display only, not an
    execution boundary. Reconnect replays from the last acknowledged ``seq``; a
    missing range surfaces as a GAP event rather than silent loss."""

    __tablename__ = "stream_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    attempt_id: Mapped[str] = mapped_column(String(36), ForeignKey("proof_attempts.id"),
                                            nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)  # STATUS|OUTPUT|EVIDENCE|GAP
    payload: Mapped[str] = mapped_column(Text, default="")
    server_ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("attempt_id", "seq", name="uq_stream_event_seq"),)


class Occurrence(Base):
    """One appearance of an :class:`Issue` on a specific surface in a specific
    execution (PRD v2 §10, Phase 9). ``finding_id`` is the legacy alias link:
    given an old Finding id you can resolve its canonical Issue through here, and
    every FindingSighting maps to exactly one Occurrence (lossless backfill)."""

    __tablename__ = "occurrences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    issue_id: Mapped[str] = mapped_column(String(36), ForeignKey("issues.id"), nullable=False,
                                          index=True)
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_executions.id"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    asset_value: Mapped[str] = mapped_column(String(256), default="")
    port: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(10), default="INFO")
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("issue_id", "execution_id", "finding_id", name="uq_occurrence_issue"),
    )


class CandidateAssociation(Base):
    """A candidate CVE association for a product/version seen on a target
    (PRD v2 §9, Phase 11).

    Kept deliberately separate from canonical Issues: a candidate is a "this
    product/version *might* be affected, pending reviewed applicability" link and
    must never inflate the actionable finding count. Matching is conservative —
    an auto-match stays ``CANDIDATE`` and is never promoted to ``SUPPORTED``
    without reviewed evidence, because an upstream version alone does not
    establish patch state (vendor backports, distro revisions, banner masking).

    All intelligence comes from a local offline snapshot; no target identifier or
    evidence is ever transmitted for enrichment.
    """

    __tablename__ = "candidate_associations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False,
                                           index=True)
    issue_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("issues.id"))
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    product: Mapped[str] = mapped_column(String(128), default="")
    version_evidence: Mapped[str] = mapped_column(String(128), default="")
    matched_cpe: Mapped[str] = mapped_column(String(256), default="")
    version_range: Mapped[str] = mapped_column(String(128), default="")
    # CANDIDATE | SUPPORTED | NOT_APPLICABLE | UNKNOWN
    applicability: Mapped[str] = mapped_column(String(16), nullable=False, default="CANDIDATE")
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")
    cvss_version: Mapped[str] = mapped_column(String(8), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    advisory_source: Mapped[str] = mapped_column(String(256), default="")
    match_rationale: Mapped[str] = mapped_column(String(256), default="")
    applicability_rule_version: Mapped[str] = mapped_column(String(16), default="")
    # Priority lane + reason codes (PRD v2 §11.1); rules, not a synthetic score.
    priority_lane: Mapped[str] = mapped_column(String(20), default="")
    priority_reasons: Mapped[list] = mapped_column(JSON, default=list)
    snapshot_version: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("target_id", "cve_id", "product", "version_evidence",
                         name="uq_candidate_association"),
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


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # TARGET | EXECUTION
    kind: Mapped[str] = mapped_column(String(12), nullable=False)
    # PDF | CSV_ZIP
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("targets.id"))
    execution_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_executions.id"))
    requested_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OperationalLog(Base):
    __tablename__ = "operational_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    level: Mapped[str] = mapped_column(String(8), default="INFO")
    message: Mapped[str] = mapped_column(Text, default="")
    target_id: Mapped[str | None] = mapped_column(String(36))
    execution_id: Mapped[str | None] = mapped_column(String(36))
    stage_id: Mapped[str | None] = mapped_column(String(48))
    correlation_id: Mapped[str | None] = mapped_column(String(48))


class MaintenanceProposal(Base):
    __tablename__ = "maintenance_proposals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    note: Mapped[str] = mapped_column(Text, default="")
    current_state: Mapped[dict] = mapped_column(JSON, default=dict)
    proposed_state: Mapped[dict] = mapped_column(JSON, default=dict)
    # PROPOSED | APPROVED | REJECTED | APPLIED
    state: Mapped[str] = mapped_column(String(12), nullable=False, default="PROPOSED")
    decided_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
