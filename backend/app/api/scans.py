"""Scans: a scan is one logical unit that may cover several targets.

Each target is one :class:`ScanExecution` sharing a ``scan_group_id``. An active
scan needs a single administrator approval for the whole group; after approval it
waits in the queue until the requester (or an administrator) presses **Start**,
and can be **Stop**ped while it runs.
"""
from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..constants import ACTIVE_SCAN_ATTESTATION
from ..db import get_db
from ..models import (
    Asset,
    AuditEvent,
    Finding,
    FindingSighting,
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
from ..services.findings import severity_rank
from ..services.scan_groups import approval_for, executions_for, group_state
from ..services.scope_db import evaluate_target_scope
from .deps import get_current_user, require_csrf

router = APIRouter(tags=["scans"])
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class CreateScan(BaseModel):
    profile: str = Field(default="PASSIVE", pattern=r"^(PASSIVE|SAFE_ACTIVE|STANDARD_ACTIVE)$")
    attestation_text: str | None = None
    rate_choice: str = Field(default="CONSERVATIVE", pattern=r"^(CONSERVATIVE|MODERATE)$")
    port_preset: str | None = None
    ports: str | None = Field(default=None, max_length=2000)


class CreateScanFlexible(CreateScan):
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
        "scan_id": ex.scan_group_id or ex.id,
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
        "approval_expires_at": ex.approval_expires_at,
        "cancel_requested": ex.cancel_requested,
        "partial": ex.partial,
        "error": ex.error,
        "stages": ex.stages,
        "tool_versions": ex.tool_versions,
        "normalized_args": ex.normalized_args,
        "parser_version": ex.parser_version,
    }


# ---------------------------------------------------------------------------
# resolving targets
# ---------------------------------------------------------------------------
def _resolve_scan_target(db: Session, user: User, target_id: str | None,
                         target_value: str | None) -> Target:
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


# ---------------------------------------------------------------------------
# creating scans
# ---------------------------------------------------------------------------
@router.get("/api/scans/port-presets")
def port_presets(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    from ..models import PortSet

    defined = [
        {"id": p.id, "name": p.name, "spec": p.spec}
        for p in db.execute(select(PortSet).order_by(PortSet.name)).scalars()
    ]
    return {"presets": PORT_PRESETS, "port_sets": defined}


def _active_options(body: CreateScan) -> dict:
    profile = profile_for(body.profile)
    try:
        ports = resolve_ports(body.port_preset, body.ports)
    except PortSpecError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {
        "ports": ports,
        "port_preset": (body.port_preset or "PROFILE_DEFAULT").upper(),
        "rate_choice": body.rate_choice,
        "rate_per_second": resolve_rate(body.rate_choice, RATE_CHOICES["CONSERVATIVE"]),
        "syn": profile.nmap_syn,
        "os_detection": profile.nmap_os_detection,
    }


def _launch_group(db: Session, user: User, targets: list[Target], body: CreateScan) -> dict:
    for t in targets:
        if not t.is_active:
            raise HTTPException(status.HTTP_409_CONFLICT, f"target {t.value} is archived")

    now = dt.datetime.now(dt.timezone.utc)
    profile = profile_for(body.profile)
    group_id = str(uuid.uuid4())
    size = len(targets)
    passive = profile.classification == "PASSIVE"

    options = {} if passive else _active_options(body)
    scope_snapshots: list[dict] = []

    if not passive:
        if (body.attestation_text or "").strip() != ACTIVE_SCAN_ATTESTATION:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "active scans require the exact ethical-use attestation text",
            )
        for t in targets:
            decision = evaluate_target_scope(db, t)
            if decision.matched_deny_rule:
                db.rollback()
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    f"target rejected by policy: {decision.reason}")
            if not decision.allowed:
                db.rollback()
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    f"{t.value} is outside approved active scope: {decision.reason}",
                )
            scope_snapshots.append({"target": t.value, **decision.as_audit_payload()})

    executions: list[ScanExecution] = []
    for i, t in enumerate(targets, start=1):
        ex = ScanExecution(
            target_id=t.id, requested_by_id=user.id, profile=body.profile,
            classification="PASSIVE" if passive else "ACTIVE",
            scan_group_id=group_id, group_seq=i, group_size=size,
            options=options,
            state="QUEUED" if passive else "DRAFT",
            queued_at=now if passive else None,
        )
        db.add(ex)
        db.flush()
        if passive:
            AuditService.append(
                db, actor=f"user:{user.username}", action="SCAN_STATE_CHANGE",
                object_type="scan_execution", object_id=ex.id,
                payload={"from": "DRAFT", "to": "QUEUED", "profile": "PASSIVE",
                         "scan_group_id": group_id},
            )
        else:
            ScanService.transition(db, ex, "AWAITING_APPROVAL", actor=f"user:{user.username}",
                                   extra_payload={"profile": body.profile,
                                                  "scan_group_id": group_id})
        executions.append(ex)

    if not passive:
        approval = ScanApproval(
            execution_id=executions[0].id, scan_group_id=group_id, target_id=targets[0].id,
            requested_by_id=user.id, profile=body.profile,
            attestation_text=ACTIVE_SCAN_ATTESTATION, requested_options=options,
            scope_at_request={"targets": scope_snapshots}, state="AWAITING_APPROVAL",
        )
        db.add(approval)
        db.flush()
        AuditService.append(
            db, actor=f"user:{user.username}", action="ATTESTATION_SUBMITTED",
            object_type="scan_approval", object_id=approval.id,
            payload={"profile": body.profile, "attestation": ACTIVE_SCAN_ATTESTATION,
                     "target_count": size},
        )
        AuditService.append(
            db, actor=f"user:{user.username}", action="APPROVAL_REQUESTED",
            object_type="scan_approval", object_id=approval.id,
            payload={"scan_group_id": group_id, "execution_ids": [e.id for e in executions],
                     "targets": [t.value for t in targets], "scope": scope_snapshots},
        )
        summary = targets[0].value + (f" and {size - 1} more" if size > 1 else "")
        for adm in db.execute(select(User).where(User.role == ROLE_ADMIN)).scalars():
            db.add(Notification(
                user_id=adm.id, kind="APPROVAL_PENDING",
                title="Active scan awaiting approval",
                body=f"{user.username} requested {body.profile} on {summary}",
            ))

    db.commit()

    if passive:
        from ..worker.tasks import run_execution

        for ex in executions:
            run_execution.delay(ex.id)

    fresh = executions_for(db, group_id)
    return {
        "scan_id": group_id,
        "state": group_state(fresh),
        "executions": [_execution_dto(e) for e in fresh],
    }


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
    return _launch_group(db, user, list(resolved.values()), body)


@router.post("/api/targets/{target_id}/scans", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_scan(target_id: str, body: CreateScan, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> dict:
    target = _access_or_404(db, user, target_id)
    result = _launch_group(db, user, [target], body)
    # keep the single-execution response shape callers already rely on
    ex = db.get(ScanExecution, result["executions"][0]["id"])
    dto = _execution_dto(ex)
    dto["scan_id"] = result["scan_id"]
    return dto


# ---------------------------------------------------------------------------
# viewing scans
# ---------------------------------------------------------------------------
def _group_summary(db: Session, executions: list[ScanExecution]) -> dict:
    first = executions[0]
    approval = approval_for(db, first.scan_group_id or first.id, executions)
    targets = []
    for e in executions:
        t = db.get(Target, e.target_id)
        targets.append({"id": e.target_id, "value": t.value if t else e.target_id,
                        "kind": t.kind if t else "", "execution_id": e.id, "state": e.state})
    return {
        "scan_id": first.scan_group_id or first.id,
        "profile": first.profile,
        "classification": first.classification,
        "state": group_state(executions),
        "requested_by_id": first.requested_by_id,
        "created_at": first.created_at,
        "started_at": min((e.started_at for e in executions if e.started_at), default=None),
        "finished_at": (max((e.finished_at for e in executions), default=None)
                        if all(e.finished_at for e in executions) else None),
        "target_count": len(executions),
        "targets": targets,
        "schedule_id": first.schedule_id,
        "approval": {
            "id": approval.id, "state": approval.state, "expires_at": approval.expires_at,
            "decided_by_id": approval.decided_by_id, "decision_reason": approval.decision_reason,
        } if approval else None,
        "options": first.options,
    }


def _visible(db: Session, user: User, executions: list[ScanExecution]) -> bool:
    if user.role == ROLE_ADMIN:
        return True
    return any(
        e.requested_by_id == user.id
        or AuthorizationService.can_view_target(db, user, e.target_id)
        for e in executions
    )


@router.get("/api/scans")
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db),
               limit: int = 100) -> list[dict]:
    rows = db.execute(
        select(ScanExecution).order_by(ScanExecution.created_at.desc()).limit(min(limit, 2000) * 4)
    ).scalars().all()

    groups: dict[str, list[ScanExecution]] = {}
    for e in rows:
        groups.setdefault(e.scan_group_id or e.id, []).append(e)

    out = []
    for gid, execs in groups.items():
        execs.sort(key=lambda e: e.group_seq)
        if not _visible(db, user, execs):
            continue
        out.append(_group_summary(db, execs))
    out.sort(key=lambda g: g["created_at"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
             reverse=True)
    return out[: min(limit, 500)]


def _host_block(db: Session, ex: ScanExecution) -> dict:
    tgt = db.get(Target, ex.target_id)
    sighting_finding_ids = {
        s.finding_id for s in db.execute(
            select(FindingSighting).where(FindingSighting.execution_id == ex.id)
        ).scalars()
    }
    findings = db.execute(
        select(Finding).where(Finding.id.in_(sighting_finding_ids or ["__none__"]))
    ).scalars().all()
    services = db.execute(
        select(Service).where(Service.target_id == ex.target_id).order_by(Service.port)
    ).scalars().all()
    assets = db.execute(
        select(Asset).where(Asset.target_id == ex.target_id).order_by(Asset.kind, Asset.value)
    ).scalars().all()
    return {
        "execution_id": ex.id,
        "target": {"id": ex.target_id, "value": tgt.value if tgt else ex.target_id,
                   "kind": tgt.kind if tgt else ""},
        "state": ex.state,
        "partial": ex.partial,
        "started_at": ex.started_at,
        "finished_at": ex.finished_at,
        "error": ex.error,
        "stages": ex.stages,
        "tool_versions": ex.tool_versions,
        "assets": [{"kind": a.kind, "value": a.value, "source": a.source,
                    "in_scope": a.in_scope, "approved": a.approved} for a in assets],
        "services": [{"port": s.port, "protocol": s.protocol, "state": s.state,
                      "product": s.product, "version": s.version} for s in services],
        "findings": sorted(
            [{"id": f.id, "severity": f.severity, "name": f.name, "rule_id": f.rule_id,
              "asset_value": f.asset_value, "port": f.port, "status": f.status,
              "evidence_summary": f.evidence_summary} for f in findings],
            key=lambda d: (-severity_rank(d["severity"]), d["rule_id"]),
        ),
    }


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)) -> dict:
    execs = executions_for(db, scan_id)
    if not execs:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if not _visible(db, user, execs):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    hosts = [_host_block(db, e) for e in execs]
    sev_counts = {s: 0 for s in _SEV_ORDER}
    for h in hosts:
        for f in h["findings"]:
            if f["status"] != "NOT_OBSERVED":
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    summary = _group_summary(db, execs)
    summary["hosts"] = hosts
    summary["summary"] = {
        "severity_counts": sev_counts,
        "total_findings": sum(sev_counts.values()),
        "needs_attention": sev_counts["CRITICAL"] + sev_counts["HIGH"],
        "hosts_total": len(hosts),
        "hosts_completed": sum(1 for h in hosts if h["state"] == "COMPLETED"),
    }
    return summary


# ---------------------------------------------------------------------------
# start / stop / cancel
# ---------------------------------------------------------------------------
def _may_control(user: User, executions: list[ScanExecution]) -> bool:
    if user.role == ROLE_ADMIN:
        return True
    return all(e.requested_by_id == user.id for e in executions)


@router.post("/api/scans/{scan_id}/start", dependencies=[Depends(require_csrf)])
def start_scan(scan_id: str, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)) -> dict:
    execs = executions_for(db, scan_id)
    if not execs or not _visible(db, user, execs):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if not _may_control(user, execs):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you may only start your own scan")

    from ..services.emergency import active_stop, blocks_execution

    stop = active_stop(db)
    now = dt.datetime.now(dt.timezone.utc)
    started = 0
    for ex in execs:
        if ex.classification == "ACTIVE" and ex.state != "APPROVED":
            continue
        if ex.state not in ("APPROVED", "DRAFT"):
            continue
        if blocks_execution(stop, ex):
            raise HTTPException(status.HTTP_409_CONFLICT, "an emergency stop is active")
        expires = ex.approval_expires_at
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=dt.timezone.utc)
            if now > expires:
                ScanService.transition(db, ex, "EXPIRED", actor=f"user:{user.username}",
                                       reason="approval window elapsed before start")
                continue
        ScanService.transition(db, ex, "QUEUED", actor=f"user:{user.username}")
        ex.queued_at = now
        started += 1

    if started == 0:
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "nothing to start (already running, or the approval expired)")

    AuditService.append(
        db, actor=f"user:{user.username}", action="SCAN_STARTED",
        object_type="scan", object_id=execs[0].scan_group_id or execs[0].id,
        payload={"executions_started": started},
    )
    db.commit()

    from ..worker.tasks import run_execution

    for ex in executions_for(db, scan_id):
        if ex.state == "QUEUED":
            run_execution.delay(ex.id)
    return get_scan(scan_id, user, db)


@router.post("/api/scans/{scan_id}/stop", dependencies=[Depends(require_csrf)])
def stop_scan(scan_id: str, body: CancelScan, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)) -> dict:
    execs = executions_for(db, scan_id)
    if not execs or not _visible(db, user, execs):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if not _may_control(user, execs):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you may only stop your own scan")

    is_admin = user.role == ROLE_ADMIN
    reason = body.reason or ("stopped by administrator" if is_admin else "stopped by requester")
    stopped = 0
    for ex in execs:
        if ex.state in TERMINAL:
            continue
        ex.cancel_requested = True
        ex.cancel_reason = reason
        if ex.state in {"DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED"}:
            ScanService.transition(db, ex, "CANCELLED", actor=f"user:{user.username}",
                                   reason=reason)
        stopped += 1
    if stopped == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is already finished")
    AuditService.append(
        db, actor=f"user:{user.username}", action="SCAN_STOP_REQUESTED",
        object_type="scan", object_id=execs[0].scan_group_id or execs[0].id,
        payload={"reason": reason, "executions_signalled": stopped},
    )
    db.commit()
    return get_scan(scan_id, user, db)


@router.post("/api/scans/{execution_id}/cancel", dependencies=[Depends(require_csrf)])
def cancel_execution(execution_id: str, body: CancelScan, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)) -> dict:
    ex = db.get(ScanExecution, execution_id)
    if ex is None or (user.role != ROLE_ADMIN
                      and not AuthorizationService.can_view_target(db, user, ex.target_id)
                      and ex.requested_by_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if user.role != ROLE_ADMIN and ex.requested_by_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you may only cancel your own scan")
    if ex.state in TERMINAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan already {ex.state}")
    ex.cancel_requested = True
    ex.cancel_reason = body.reason or "cancelled by requester"
    AuditService.append(
        db, actor=f"user:{user.username}", action="SCAN_CANCEL_REQUESTED",
        object_type="scan_execution", object_id=ex.id, payload={"reason": ex.cancel_reason},
    )
    if ex.state in {"DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED"}:
        ScanService.transition(db, ex, "CANCELLED", actor=f"user:{user.username}",
                               reason=ex.cancel_reason)
    db.commit()
    return _execution_dto(db.get(ScanExecution, ex.id))


# ---------------------------------------------------------------------------
# per-target detail (unchanged)
# ---------------------------------------------------------------------------
@router.get("/api/targets/{target_id}/observations")
def list_observations(target_id: str, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Observation).where(Observation.target_id == target_id)
        .order_by(Observation.kind, Observation.key)
    ).scalars().all()
    return [
        {"id": o.id, "kind": o.kind, "key": o.key, "value": o.value, "asset_id": o.asset_id,
         "source_tool": o.source_tool, "first_seen_at": o.first_seen_at,
         "last_seen_at": o.last_seen_at}
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
        {"id": s.id, "asset_id": s.asset_id, "port": s.port, "protocol": s.protocol,
         "state": s.state, "product": s.product, "version": s.version,
         "confidence": s.confidence, "first_seen_at": s.first_seen_at,
         "last_seen_at": s.last_seen_at}
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
                       "detail": f"{ex.profile} scan {ex.id[:8]} ({ex.state})", "ref": ex.id})
        if ex.finished_at:
            events.append({"at": ex.finished_at, "kind": "scan_finished",
                           "detail": f"scan {ex.id[:8]} -> {ex.state}"
                                     + (" (partial)" if ex.partial else ""), "ref": ex.id})
    for a in db.execute(select(Asset).where(Asset.target_id == target_id)).scalars():
        events.append({"at": a.first_seen_at, "kind": "asset_first_seen",
                       "detail": f"{a.kind} {a.value}" + ("" if a.approved else " (unapproved)"),
                       "ref": a.id})
    for f in db.execute(select(Finding).where(Finding.target_id == target_id)).scalars():
        events.append({"at": f.first_seen_at, "kind": "finding_first_observed",
                       "detail": f"[{f.severity}] {f.name} on {f.asset_value}"
                                 + (" — NOT OBSERVED in latest scan"
                                    if f.status == "NOT_OBSERVED" else ""), "ref": f.id})
    for ev in db.execute(
        select(AuditEvent).where(
            AuditEvent.object_type == "target", AuditEvent.object_id == target_id)
    ).scalars():
        events.append({"at": ev.ts, "kind": f"audit:{ev.action}", "detail": ev.action,
                       "ref": str(ev.seq)})
    events.sort(key=lambda e: (e["at"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)))
    return events
