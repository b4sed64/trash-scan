"""Administrator approval queue for active scans (PRD §8.1)."""
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
from .deps import require_admin, require_csrf

router = APIRouter(prefix="/api/approvals", tags=["approvals"], dependencies=[Depends(require_admin)])


class Decision(BaseModel):
    reason: str = Field(default="", max_length=512)


def _dto(db: Session, a: ScanApproval) -> dict:
    ex = db.get(ScanExecution, a.execution_id)
    target = db.get(Target, a.target_id)
    requester = db.get(User, a.requested_by_id) if a.requested_by_id else None
    return {
        "id": a.id,
        "execution_id": a.execution_id,
        "state": a.state,
        "profile": a.profile,
        "target": {"id": target.id, "value": target.value, "kind": target.kind} if target else None,
        "requested_by": requester.username if requester else None,
        "attestation_text": a.attestation_text,
        "requested_options": a.requested_options,
        "scope_at_request": a.scope_at_request,
        "created_at": a.created_at,
        "expires_at": a.expires_at,
        "decided_by_id": a.decided_by_id,
        "decided_at": a.decided_at,
        "decision_reason": a.decision_reason,
        "execution_state": ex.state if ex else None,
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

    execution = db.get(ScanExecution, approval.execution_id)
    if execution is None or execution.state != "AWAITING_APPROVAL":
        raise HTTPException(status.HTTP_409_CONFLICT, "execution is not awaiting approval")

    now = dt.datetime.now(dt.timezone.utc)
    window = dt.timedelta(minutes=get_settings().approval_window_minutes)

    approval.state = "APPROVED"
    approval.decided_by_id = admin.id
    approval.decided_at = now
    approval.expires_at = now + window

    execution.approval_id = approval.id
    execution.approved_at = now
    execution.approval_expires_at = now + window

    # AWAITING_APPROVAL -> APPROVED -> QUEUED (one approved execution, 2h to start).
    ScanService.transition(db, execution, "APPROVED", actor=f"user:{admin.username}",
                           extra_payload={"expires_at": approval.expires_at.isoformat()})
    ScanService.transition(db, execution, "QUEUED", actor=f"user:{admin.username}")
    execution.queued_at = now

    AuditService.append(
        db, actor=f"user:{admin.username}", action="APPROVAL_GRANTED",
        object_type="scan_approval", object_id=approval.id,
        payload={"execution_id": execution.id, "expires_at": approval.expires_at.isoformat()},
    )
    if approval.occurrence_id:
        occ = db.get(ScheduleOccurrence, approval.occurrence_id)
        if occ:
            occ.state = "RUNNING"
    if execution.requested_by_id:
        db.add(Notification(
            user_id=execution.requested_by_id, kind="SCAN_APPROVED",
            title="Active scan approved",
            body=f"Approved; must start within {get_settings().approval_window_minutes} minutes.",
        ))
    db.commit()

    from ..worker.tasks import run_execution

    run_execution.delay(execution.id)
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

    execution = db.get(ScanExecution, approval.execution_id)
    if execution and execution.state == "AWAITING_APPROVAL":
        ScanService.transition(db, execution, "DENIED", actor=f"user:{admin.username}",
                               reason=body.reason or "denied by administrator")
    if approval.occurrence_id:
        occ = db.get(ScheduleOccurrence, approval.occurrence_id)
        if occ:
            occ.state = "DENIED"
    AuditService.append(
        db, actor=f"user:{admin.username}", action="APPROVAL_DENIED",
        object_type="scan_approval", object_id=approval.id,
        payload={"execution_id": approval.execution_id, "reason": body.reason},
    )
    db.commit()
    return _dto(db, db.get(ScanApproval, approval.id))
