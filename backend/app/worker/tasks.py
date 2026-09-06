"""Celery tasks: execution runner, scheduler tick, lifecycle sweep."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from ..celery_app import celery_app
from ..db import SessionLocal
from ..models import ScanExecution
from ..services.audit_service import AuditService
from ..services.execution_service import ScanService
from . import runner


@celery_app.task(name="app.worker.tasks.run_execution", bind=True, max_retries=0)
def run_execution(self, execution_id: str) -> str:  # noqa: ARG001
    return runner.execute(execution_id, enqueue=_enqueue)


@celery_app.task(name="app.worker.tasks.scheduler_tick")
def scheduler_tick() -> dict:
    from ..services import schedule_service

    with SessionLocal() as db:
        return schedule_service.tick(db, enqueue=_enqueue)


@celery_app.task(name="app.worker.tasks.lifecycle_sweep")
def lifecycle_sweep() -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    expired = timed_out = requeued = 0
    with SessionLocal() as db:
        # Approval window (SCAN-03): unused approval expires.
        for ex in db.execute(
            select(ScanExecution).where(
                ScanExecution.state.in_(("AWAITING_APPROVAL", "APPROVED")),
                ScanExecution.approval_expires_at.is_not(None),
                ScanExecution.approval_expires_at < now,
            )
        ).scalars():
            if ScanService.transition(db, ex, "EXPIRED", actor="system:sweeper",
                                      reason="approval window elapsed"):
                expired += 1

        # Runtime cap (SCAN-04): measured from RUNNING, independent of approval.
        for ex in db.execute(
            select(ScanExecution).where(
                ScanExecution.state.in_(("RUNNING", "CANCELLING")),
                ScanExecution.runtime_deadline_at.is_not(None),
                ScanExecution.runtime_deadline_at < now,
            )
        ).scalars():
            ex.cancel_requested = True
            ex.partial = True
            if ex.state == "CANCELLING":
                ex.state = "RUNNING"  # allow the TIMED_OUT transition
            if ScanService.transition(db, ex, "TIMED_OUT", actor="system:sweeper",
                                      reason="maximum runtime reached"):
                timed_out += 1
                AuditService.append(
                    db, actor="system:sweeper", action="SCAN_TERMINATED",
                    object_type="scan_execution", object_id=ex.id,
                    payload={"reason": "TIMED_OUT"},
                )

        # Re-enqueue executions stuck in QUEUED once capacity frees.
        for ex in db.execute(
            select(ScanExecution).where(ScanExecution.state == "QUEUED")
        ).scalars():
            if ScanService.capacity_available(db, ex):
                requeued += 1
                _enqueue(ex.id)

        db.commit()
    return {"expired": expired, "timed_out": timed_out, "requeued": requeued}


def _enqueue(execution_id: str) -> None:
    run_execution.delay(execution_id)
