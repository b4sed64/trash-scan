"""Administrator approval queue for active scans (PRD §8.1).

One approval covers a whole scan (all its per-target executions). Approving does
**not** start the scan — the requester (or an administrator) presses Start, which
must happen within the two-hour window.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Notification, ScanApproval, ScanExecution, ScheduleOccurrence, Target, User
from ..services import AuditService
from ..services.execution_service import ScanService
from ..services.scan_groups import executions_for
from .deps import require_admin, require_csrf

router = APIRouter(prefix="/api/approvals", tags=["approvals"], dependencies=[Depends(require_admin)])


class Decision(BaseModel):
    reason: str = Field(default="", max_length=512)


def _group_executions(db: Session, approval: ScanApproval) -> list[ScanExecution]:
    return executions_for(db, approval.scan_group_id or approval.execution_id)


def _dto(db: Session, a: ScanApproval) -> dict:
    execs = _group_executions(db, a)
    targets = []
    for e in execs:
        t = db.get(Target, e.target_id)
        targets.append({"id": e.target_id, "value": t.value if t else e.target_id,
                        "kind": t.kind if t else "", "execution_id": e.id, "state": e.state})
    requester = db.get(User, a.requested_by_id) if a.requested_by_id else None
    first_target = db.get(Target, a.target_id)
    return {
        "id": a.id,
        "scan_id": a.scan_group_id or a.execution_id,
        "execution_id": a.execution_id,
        "state": a.state,
        "profile": a.profile,
        "target": {"id": first_target.id, "value": first_target.value, "kind": first_target.kind}
        if first_target else None,
        "targets": targets,
        "target_count": len(targets),
        "requested_by": requester.username if requester else None,
        "attestation_text": a.attestation_text,
        "requested_options": a.requested_options,
        "scope_at_request": a.scope_at_request,
        "created_at": a.created_at,
        "expires_at": a.expires_at,
        "decided_by_id": a.decided_by_id,
        "decided_at": a.decided_at,
        "decision_reason": a.decision_reason,
        "execution_state": execs[0].state if execs else None,
        "schedule_id": a.schedule_id,
    }


@router.get("")
def list_approvals(db: Session = Depends(get_db), include_decided: bool = True) -> list[dict]:
    stmt = select(ScanApproval).order_by(ScanApproval.created_at.desc()).limit(200)
    if not include_decided:
        stmt = (
            select(ScanApproval)
            .where(ScanApproval.state == "AWAITING_APPROVAL")
            .order_by(ScanApproval.created_at.desc())
        )
    return [_dto(db, a) for a in db.execute(stmt).scalars()]


@router.get("/{approval_id}")
def get_approval(approval_id: str, db: Session = Depends(get_db)) -> dict:
    approval = db.get(ScanApproval, approval_id)
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    return _dto(db, approval)


@router.post("/{approval_id}/approve", dependencies=[Depends(require_csrf)])
def approve(approval_id: str, admin: User = Depends(require_admin),
            db: Session = Depends(get_db)) -> dict:
    approval = db.get(ScanApproval, approval_id)
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    if approval.state != "AWAITING_APPROVAL":
        raise HTTPException(status.HTTP_409_CONFLICT, f"approval already {approval.state}")

    execs = _group_executions(db, approval)
    if not execs or not all(e.state == "AWAITING_APPROVAL" for e in execs):
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is not awaiting approval")

    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(minutes=get_settings().approval_window_minutes)

    approval.state = "APPROVED"
    approval.decided_by_id = admin.id
    approval.decided_at = now
    approval.expires_at = expires

    for ex in execs:
        ex.approval_id = approval.id
        ex.approved_at = now
        ex.approval_expires_at = expires
        # AWAITING_APPROVAL -> APPROVED. The scan then waits for a manual Start.
        ScanService.transition(db, ex, "APPROVED", actor=f"user:{admin.username}",
                               extra_payload={"expires_at": expires.isoformat()})

    AuditService.append(
        db, actor=f"user:{admin.username}", action="APPROVAL_GRANTED",
        object_type="scan_approval", object_id=approval.id,
        payload={"scan_group_id": approval.scan_group_id, "execution_ids": [e.id for e in execs],
                 "expires_at": expires.isoformat()},
    )
    scheduled = bool(approval.occurrence_id)
    if scheduled:
        occ = db.get(ScheduleOccurrence, approval.occurrence_id)
        # A scheduled occurrence starts on approval — the schedule is the intent.
        for ex in execs:
            if ex.state == "APPROVED":
                ScanService.transition(db, ex, "QUEUED", actor=f"user:{admin.username}")
                ex.queued_at = now
        if occ:
            occ.state = "RUNNING"

    if approval.requested_by_id:
        db.add(Notification(
            user_id=approval.requested_by_id, kind="SCAN_APPROVED",
            title="Active scan approved",
            body=("Approved and started (scheduled)." if scheduled else
                  f"Approved. Press Start within {get_settings().approval_window_minutes} minutes."),
        ))
    db.commit()

    if scheduled:
        from ..worker.tasks import run_execution

        for ex in _group_executions(db, db.get(ScanApproval, approval.id)):
            if ex.state == "QUEUED":
                run_execution.delay(ex.id)
    return _dto(db, db.get(ScanApproval, approval.id))


@router.post("/{approval_id}/deny", dependencies=[Depends(require_csrf)])
def deny(approval_id: str, body: Decision, admin: User = Depends(require_admin),
         db: Session = Depends(get_db)) -> dict:
    approval = db.get(ScanApproval, approval_id)
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    if approval.state != "AWAITING_APPROVAL":
        raise HTTPException(status.HTTP_409_CONFLICT, f"approval already {approval.state}")

    approval.state = "DENIED"
    approval.decided_by_id = admin.id
    approval.decided_at = dt.datetime.now(dt.timezone.utc)
    approval.decision_reason = body.reason

    for ex in _group_executions(db, approval):
        if ex.state == "AWAITING_APPROVAL":
            ScanService.transition(db, ex, "DENIED", actor=f"user:{admin.username}",
                                   reason=body.reason or "denied by administrator")
    if approval.occurrence_id:
        occ = db.get(ScheduleOccurrence, approval.occurrence_id)
        if occ:
            occ.state = "DENIED"
    AuditService.append(
        db, actor=f"user:{admin.username}", action="APPROVAL_DENIED",
        object_type="scan_approval", object_id=approval.id,
        payload={"scan_group_id": approval.scan_group_id, "reason": body.reason},
    )
    db.commit()
    return _dto(db, db.get(ScanApproval, approval.id))
