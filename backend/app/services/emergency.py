"""Emergency stop (PRD §23.2).

An administrator stop has priority over ordinary queue work: it marks selected
executions for cancellation and prevents scheduled/active jobs from starting
until an administrator clears it.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import EmergencyStop, ScanExecution
from .audit_service import AuditService
from .execution_service import TERMINAL, ScanService

ACTIVE_STATES = ("REQUESTED", "CONFIRMED", "FAILED")


def active_stop(db: Session) -> EmergencyStop | None:
    return db.execute(
        select(EmergencyStop)
        .where(EmergencyStop.state.in_(ACTIVE_STATES))
        .order_by(EmergencyStop.requested_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def blocks_execution(stop: EmergencyStop | None, execution: ScanExecution) -> bool:
    if stop is None:
        return False
    if stop.target_scope == "ALL":
        return True
    return execution.id in (stop.execution_ids or [])


def request_stop(db: Session, *, actor: str, requester_id: str, scope: str,
                 execution_ids: list[str], note: str) -> EmergencyStop:
    stop = EmergencyStop(
        requested_by_id=requester_id, target_scope=scope,
        execution_ids=execution_ids if scope == "SELECTED" else [], state="REQUESTED", note=note,
    )
    db.add(stop)
    db.flush()

    targets = db.execute(
        select(ScanExecution).where(
            ScanExecution.state.in_(("DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED",
                                     "RUNNING", "CANCELLING"))
        )
    ).scalars().all()
    stopped = 0
    for ex in targets:
        if scope == "SELECTED" and ex.id not in execution_ids:
            continue
        ex.cancel_requested = True
        ex.cancel_reason = "emergency stop"
        if ex.state in {"DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED"}:
            ScanService.transition(db, ex, "CANCELLED", actor=actor, reason="emergency stop")
        stopped += 1

    AuditService.append(
        db, actor=actor, action="EMERGENCY_STOP_REQUESTED",
        object_type="emergency_stop", object_id=stop.id,
        payload={"scope": scope, "execution_ids": execution_ids, "executions_signalled": stopped,
                 "note": note},
    )
    return stop


def reconcile(db: Session) -> None:
    """Move REQUESTED -> CONFIRMED once every signalled execution is terminal."""
    for stop in db.execute(
        select(EmergencyStop).where(EmergencyStop.state == "REQUESTED")
    ).scalars():
        q = select(ScanExecution).where(
            ScanExecution.state.notin_(TERMINAL), ScanExecution.cancel_requested.is_(True)
        )
        if stop.target_scope == "SELECTED":
            q = q.where(ScanExecution.id.in_(stop.execution_ids or ["__none__"]))
        outstanding = db.execute(q).scalars().first()
        if outstanding is None:
            stop.state = "CONFIRMED"
            AuditService.append(
                db, actor="system:sweeper", action="EMERGENCY_STOP_CONFIRMED",
                object_type="emergency_stop", object_id=stop.id, payload={},
            )


def clear_stop(db: Session, stop: EmergencyStop, *, actor: str, cleared_by: str) -> None:
    stop.state = "CLEARED"
    stop.cleared_by_id = cleared_by
    stop.cleared_at = dt.datetime.now(dt.timezone.utc)
    AuditService.append(
        db, actor=actor, action="EMERGENCY_STOP_CLEARED",
        object_type="emergency_stop", object_id=stop.id, payload={},
    )
