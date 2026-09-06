"""ScanService — the scan-execution state machine (PRD §10, §11.3).

All enumerated states are the stable uppercase values from the PRD. Transitions
are validated here; illegal transitions raise. Every transition writes one audit
event and (for requester-visible states) one notification. Terminal states are
idempotent so a duplicated queue message cannot double-count (NFR-08).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Notification, ScanExecution
from .audit_service import AuditService

TERMINAL = {"COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"}

ALLOWED: dict[str, set[str]] = {
    "DRAFT": {"AWAITING_APPROVAL", "QUEUED", "CANCELLED"},
    "AWAITING_APPROVAL": {"APPROVED", "DENIED", "CANCELLED", "EXPIRED"},
    # FAILED from APPROVED/QUEUED covers a pre-launch scope re-check failure
    # (PRD §6.4 / §24): the execution never reaches a tool but must still land in
    # an accurate terminal state.
    "APPROVED": {"QUEUED", "CANCELLED", "EXPIRED", "FAILED"},
    "QUEUED": {"RUNNING", "CANCELLED", "EXPIRED", "CANCELLING", "FAILED"},
    "RUNNING": {"COMPLETED", "FAILED", "CANCELLING", "TIMED_OUT"},
    "CANCELLING": {"CANCELLED", "FAILED"},
    "COMPLETED": set(),
    "FAILED": set(),
    "TIMED_OUT": set(),
    "DENIED": set(),
    "EXPIRED": set(),
    "CANCELLED": set(),
}

_REQUESTER_NOTIFY = {
    "APPROVED": ("Scan approved", "Your scan request was approved."),
    "DENIED": ("Scan denied", "Your scan request was denied."),
    "EXPIRED": ("Scan approval expired", "The approval was not used in time."),
    "RUNNING": ("Scan started", "Your scan is running."),
    "COMPLETED": ("Scan completed", "Your scan completed and results were normalized."),
    "FAILED": ("Scan failed", "Your scan ended unexpectedly."),
    "CANCELLED": ("Scan cancelled", "Your scan was cancelled."),
    "TIMED_OUT": ("Scan timed out", "Your scan hit the two-hour runtime limit."),
}


class IllegalTransition(Exception):
    pass


class ScanService:
    @staticmethod
    def can_transition(current: str, target: str) -> bool:
        return target in ALLOWED.get(current, set())

    @staticmethod
    def transition(
        db: Session,
        execution: ScanExecution,
        target_state: str,
        *,
        actor: str,
        reason: str | None = None,
        extra_payload: dict | None = None,
    ) -> bool:
        """Move ``execution`` to ``target_state``. Returns False (no-op) if the
        execution is already in a terminal state — this keeps requeues idempotent.
        """
        if execution.state == target_state:
            return False
        if execution.state in TERMINAL:
            return False
        if not ScanService.can_transition(execution.state, target_state):
            raise IllegalTransition(f"{execution.state} -> {target_state}")

        now = dt.datetime.now(dt.timezone.utc)
        prev = execution.state
        execution.state = target_state

        if target_state == "QUEUED":
            execution.queued_at = execution.queued_at or now
        elif target_state == "RUNNING":
            execution.started_at = now
            execution.runtime_deadline_at = now + dt.timedelta(
                minutes=get_settings().max_runtime_minutes
            )
        elif target_state in TERMINAL:
            execution.finished_at = now
        if reason:
            execution.cancel_reason = reason

        payload = {"from": prev, "to": target_state}
        if reason:
            payload["reason"] = reason
        if extra_payload:
            payload.update(extra_payload)
        AuditService.append(
            db, actor=actor, action="SCAN_STATE_CHANGE",
            object_type="scan_execution", object_id=execution.id, payload=payload,
        )

        if target_state in _REQUESTER_NOTIFY and execution.requested_by_id:
            title, body = _REQUESTER_NOTIFY[target_state]
            db.add(Notification(
                user_id=execution.requested_by_id, kind=f"SCAN_{target_state}",
                title=title, body=f"{body} (target scan {execution.id[:8]})",
            ))
        return True

    # --- concurrency / rate gates (SCAN-08) --------------------------------
    @staticmethod
    def active_slots(db: Session) -> tuple[int, dict[str, int]]:
        rows = db.execute(
            select(ScanExecution.target_id, func.count())
            .where(ScanExecution.state.in_(("QUEUED", "RUNNING", "CANCELLING")))
            .group_by(ScanExecution.target_id)
        ).all()
        per_target = {tid: n for tid, n in rows}
        return sum(per_target.values()), per_target

    @staticmethod
    def capacity_available(db: Session, execution: ScanExecution) -> bool:
        s = get_settings()
        total, per_target = ScanService.active_slots(db)
        # The execution itself is already counted while QUEUED.
        running_here = per_target.get(execution.target_id, 0)
        if execution.state == "QUEUED":
            total -= 1
            running_here -= 1
        return (
            total < s.max_global_executions
            and running_here < s.max_per_target_executions
        )
