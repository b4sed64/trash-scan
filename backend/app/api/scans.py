"""Scan executions: create (passive), list, detail, cancel, and target history."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..constants import ACTIVE_SCAN_ATTESTATION
from ..db import get_db
from ..models import (
    Asset,
    AuditEvent,
    Notification,
    Observation,
    ScanApproval,
    ScanExecution,
    Service,
    Target,
    User,
)
from ..scan_profiles import (
    PORT_PRESETS,
    RATE_CHOICES,
    PortSpecError,
    profile_for,
    resolve_ports,
    resolve_rate,
)
from ..services import AuditService, AuthorizationService, ScopeError, canonicalize_target
from ..services.authorization_service import PermissionDenied, ROLE_ADMIN
from ..services.execution_service import TERMINAL, ScanService
from ..services.scope_db import evaluate_target_scope
from .deps import get_current_user, require_csrf

router = APIRouter(tags=["scans"])


class CreateScan(BaseModel):
    profile: str = Field(default="PASSIVE", pattern=r"^(PASSIVE|SAFE_ACTIVE|STANDARD_ACTIVE)$")
    attestation_text: str | None = None
    rate_choice: str = Field(default="CONSERVATIVE", pattern=r"^(CONSERVATIVE|MODERATE)$")
    # Port selection for active scans: a preset name and/or a custom spec.
    port_preset: str | None = None
    ports: str | None = Field(default=None, max_length=2000)


class CreateScanFlexible(CreateScan):
    # Any combination identifies one or more targets to scan.
    target_id: str | None = None
    target_value: str | None = Field(default=None, max_length=256)
    target_ids: list[str] = Field(default_factory=list)
    target_values: list[str] = Field(default_factory=list, max_length=50)


class CancelScan(BaseModel):
    reason: str = Field(default="", max_length=256)


def _access_or_404(db: Session, user: User, target_id: str):
    try:
        return AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc


def _execution_dto(ex: ScanExecution) -> dict:
    return {
        "id": ex.id,
        "target_id": ex.target_id,
        "profile": ex.profile,
        "classification": ex.classification,
        "state": ex.state,
        "requested_by_id": ex.requested_by_id,
        "schedule_id": ex.schedule_id,
        "created_at": ex.created_at,
        "queued_at": ex.queued_at,
        "started_at": ex.started_at,
        "finished_at": ex.finished_at,
        "runtime_deadline_at": ex.runtime_deadline_at,
        "cancel_requested": ex.cancel_requested,
        "partial": ex.partial,
        "error": ex.error,
        "stages": ex.stages,
        "tool_versions": ex.tool_versions,
        "normalized_args": ex.normalized_args,
        "parser_version": ex.parser_version,
    }


def _visible_execution(db: Session, user: User, execution_id: str) -> ScanExecution:
    ex = db.get(ScanExecution, execution_id)
    if ex is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if user.role != ROLE_ADMIN and not AuthorizationService.can_view_target(db, user, ex.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return ex


def _resolve_scan_target(db: Session, user: User, target_id: str | None,
                         target_value: str | None) -> Target:
    """Resolve the target to scan from an id or a typed host / IP / CIDR.

    A typed value is canonicalised and matched against existing targets. If none
    exists an administrator may create it on the fly (deny rules still apply); a
    scanner cannot — they must be assigned a target an administrator defined.
    """
    if target_id:
        return _access_or_404(db, user, target_id)
    if not target_value or not target_value.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "provide a target to scan (choose one or type a host/IP/CIDR)")
    try:
        kind, canonical = canonicalize_target(target_value)
    except ScopeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    existing = db.execute(
        select(Target).where(Target.kind == kind, Target.value == canonical)
    ).scalar_one_or_none()
    if existing is not None:
        return _access_or_404(db, user, existing.id)

    if user.role != ROLE_ADMIN:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{canonical} is not a defined target; ask an administrator to add and assign it",
        )

    target = Target(kind=kind, value=canonical, note="ad-hoc (created from a scan request)",
                    created_by_id=user.id)
    db.add(target)
    db.flush()
    decision = evaluate_target_scope(db, target)
    if decision.matched_deny_rule:
        db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"target rejected by policy: {decision.reason}")
    AuditService.append(
        db, actor=f"user:{user.username}", action="TARGET_CREATED",
        object_type="target", object_id=target.id,
        payload={"kind": kind, "value": canonical, "is_public": False, "via": "scan_request"},
    )
    return target


@router.get("/api/scans/port-presets")
def port_presets(_: User = Depends(get_current_user)) -> dict:
    return {"presets": PORT_PRESETS}


@router.post("/api/scans", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_scan_flexible(body: CreateScanFlexible, user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)) -> dict:
    ids = [t for t in ([body.target_id] if body.target_id else []) + list(body.target_ids) if t]
    values = [
        v for v in ([body.target_value] if body.target_value else []) + list(body.target_values)
        if v and v.strip()
    ]
    if not ids and not values:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "select at least one target, or type a host / IP / CIDR")

    resolved: dict[str, Target] = {}
    for tid in ids:
        t = _resolve_scan_target(db, user, tid, None)
        resolved[t.id] = t
    for value in values:
        t = _resolve_scan_target(db, user, None, value)
        resolved[t.id] = t

    executions = [_launch_scan(db, user, t, body) for t in resolved.values()]
    return {"executions": executions}


@router.post("/api/targets/{target_id}/scans", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_scan(target_id: str, body: CreateScan, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> dict:
    target = _access_or_404(db, user, target_id)
    return _launch_scan(db, user, target, body)


def _launch_scan(db: Session, user: User, target: Target, body: CreateScan) -> dict:
    if not target.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, "target is archived")

    now = dt.datetime.now(dt.timezone.utc)
    profile = profile_for(body.profile)

    if profile.classification == "PASSIVE":
        execution = ScanExecution(
            target_id=target.id, requested_by_id=user.id, profile="PASSIVE",
            classification="PASSIVE", state="QUEUED", queued_at=now,
        )
        db.add(execution)
        db.flush()
        AuditService.append(
            db, actor=f"user:{user.username}", action="SCAN_STATE_CHANGE",
            object_type="scan_execution", object_id=execution.id,
            payload={"from": "DRAFT", "to": "QUEUED", "profile": "PASSIVE"},
        )
        db.commit()
        from ..worker.tasks import run_execution

        run_execution.delay(execution.id)
        return _execution_dto(db.get(ScanExecution, execution.id))

    # --- active scan request (PRD §8.1) --------------------------------
    if (body.attestation_text or "").strip() != ACTIVE_SCAN_ATTESTATION:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "active scans require the exact ethical-use attestation text",
        )

    decision = evaluate_target_scope(db, target)
    if decision.matched_deny_rule:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"target rejected by policy: {decision.reason}")
    if not decision.allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"target is outside approved active scope: {decision.reason}")

    try:
        ports = resolve_ports(body.port_preset, body.ports)
    except PortSpecError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    options = {
        # None -> the profile default port set from configuration.
        "ports": ports,
        "port_preset": (body.port_preset or "PROFILE_DEFAULT").upper(),
        "rate_choice": body.rate_choice,
        "rate_per_second": resolve_rate(body.rate_choice, RATE_CHOICES["CONSERVATIVE"]),
        "syn": profile.nmap_syn,
        "os_detection": profile.nmap_os_detection,
    }

    execution = ScanExecution(
        target_id=target.id, requested_by_id=user.id, profile=body.profile,
        classification="ACTIVE", state="DRAFT", options=options,
    )
    db.add(execution)
    db.flush()
    ScanService.transition(db, execution, "AWAITING_APPROVAL", actor=f"user:{user.username}",
                           extra_payload={"profile": body.profile})

    approval = ScanApproval(
        execution_id=execution.id, target_id=target.id, requested_by_id=user.id,
        profile=body.profile, attestation_text=ACTIVE_SCAN_ATTESTATION,
        requested_options=options, scope_at_request=decision.as_audit_payload(),
        state="AWAITING_APPROVAL",
    )
    db.add(approval)
    db.flush()

    AuditService.append(
        db, actor=f"user:{user.username}", action="ATTESTATION_SUBMITTED",
        object_type="scan_approval", object_id=approval.id,
        payload={"profile": body.profile, "attestation": ACTIVE_SCAN_ATTESTATION},
    )
    AuditService.append(
        db, actor=f"user:{user.username}", action="APPROVAL_REQUESTED",
        object_type="scan_approval", object_id=approval.id,
        payload={"execution_id": execution.id, "scope": decision.as_audit_payload()},
    )
    for admin in db.execute(select(User).where(User.role == ROLE_ADMIN)).scalars():
        db.add(Notification(
            user_id=admin.id, kind="APPROVAL_PENDING",
            title="Active scan awaiting approval",
            body=f"{user.username} requested {body.profile} on {target.value}",
        ))
    db.commit()
    return _execution_dto(db.get(ScanExecution, execution.id))


@router.get("/api/scans")
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db),
               limit: int = 100) -> list[dict]:
    stmt = select(ScanExecution).order_by(ScanExecution.created_at.desc()).limit(min(limit, 500))
    if user.role != ROLE_ADMIN:
        visible = [t.id for t in AuthorizationService.visible_targets(db, user)]
        stmt = (
            select(ScanExecution)
            .where(
                or_(
                    ScanExecution.target_id.in_(visible or ["__none__"]),
                    ScanExecution.requested_by_id == user.id,
                )
            )
            .order_by(ScanExecution.created_at.desc())
            .limit(min(limit, 500))
        )
    return [_execution_dto(e) for e in db.execute(stmt).scalars()]


@router.get("/api/scans/{execution_id}")
def get_scan(execution_id: str, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)) -> dict:
    return _execution_dto(_visible_execution(db, user, execution_id))


@router.post("/api/scans/{execution_id}/cancel", dependencies=[Depends(require_csrf)])
def cancel_scan(execution_id: str, body: CancelScan, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> dict:
    ex = _visible_execution(db, user, execution_id)
    is_admin = user.role == ROLE_ADMIN
    if not is_admin and ex.requested_by_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you may only cancel your own scan")
    if ex.state in TERMINAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan already {ex.state}")

    ex.cancel_requested = True
    ex.cancel_reason = body.reason or ("cancelled by administrator" if is_admin else "cancelled by requester")
    AuditService.append(
        db, actor=f"user:{user.username}", action="SCAN_CANCEL_REQUESTED",
        object_type="scan_execution", object_id=ex.id, payload={"reason": ex.cancel_reason},
    )
    # If not yet running, resolve immediately; a running scan is stopped by the worker.
    if ex.state in {"DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED"}:
        ScanService.transition(db, ex, "CANCELLED", actor=f"user:{user.username}",
                               reason=ex.cancel_reason)
    db.commit()
    return _execution_dto(db.get(ScanExecution, ex.id))


@router.get("/api/targets/{target_id}/observations")
def list_observations(target_id: str, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Observation).where(Observation.target_id == target_id)
        .order_by(Observation.kind, Observation.key)
    ).scalars().all()
    return [
        {
            "id": o.id, "kind": o.kind, "key": o.key, "value": o.value,
            "asset_id": o.asset_id, "source_tool": o.source_tool,
            "first_seen_at": o.first_seen_at, "last_seen_at": o.last_seen_at,
        }
        for o in rows
    ]


@router.get("/api/targets/{target_id}/services")
def list_services(target_id: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Service).where(Service.target_id == target_id)
        .order_by(Service.asset_id, Service.port)
    ).scalars().all()
    return [
        {
            "id": s.id, "asset_id": s.asset_id, "port": s.port, "protocol": s.protocol,
            "state": s.state, "product": s.product, "version": s.version,
            "confidence": s.confidence, "first_seen_at": s.first_seen_at,
            "last_seen_at": s.last_seen_at,
        }
        for s in rows
    ]


@router.get("/api/targets/{target_id}/timeline")
def target_timeline(target_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    events: list[dict] = []

    for ex in db.execute(
        select(ScanExecution).where(ScanExecution.target_id == target_id)
    ).scalars():
        events.append({"at": ex.created_at, "kind": "scan_created",
                       "detail": f"{ex.profile} scan {ex.id[:8]} ({ex.state})",
                       "ref": ex.id})
        if ex.finished_at:
            events.append({"at": ex.finished_at, "kind": "scan_finished",
                           "detail": f"scan {ex.id[:8]} -> {ex.state}"
                                     + (" (partial)" if ex.partial else ""),
                           "ref": ex.id})

    for a in db.execute(select(Asset).where(Asset.target_id == target_id)).scalars():
        events.append({"at": a.first_seen_at, "kind": "asset_first_seen",
                       "detail": f"{a.kind} {a.value}"
                                 + ("" if a.approved else " (unapproved)"),
                       "ref": a.id})

    from ..models import Finding

    for f in db.execute(select(Finding).where(Finding.target_id == target_id)).scalars():
        events.append({"at": f.first_seen_at, "kind": "finding_first_observed",
                       "detail": f"[{f.severity}] {f.name} on {f.asset_value}"
                                 + (" — NOT OBSERVED in latest scan" if f.status == "NOT_OBSERVED"
                                    else ""),
                       "ref": f.id})

    for ev in db.execute(
        select(AuditEvent).where(
            AuditEvent.object_type == "target", AuditEvent.object_id == target_id
        )
    ).scalars():
        events.append({"at": ev.ts, "kind": f"audit:{ev.action}",
                       "detail": ev.action, "ref": str(ev.seq)})

    events.sort(key=lambda e: (e["at"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)))
    return events
