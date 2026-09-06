"""Schedule evaluation (PRD §8.2, §11.5).

* Passive occurrences run without approval.
* Active occurrences are created paused (``AWAITING_APPROVAL``) — never run
  automatically.
* A missed occurrence is recorded as ``EXPIRED`` and never silently run later.
* Changing the attestation-relevant fields invalidates a stored attestation.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Notification,
    ScanApproval,
    ScanExecution,
    Schedule,
    ScheduleOccurrence,
    User,
)
from .audit_service import AuditService
from .execution_service import TERMINAL

ATTESTATION_FIELDS = ("target_id", "profile", "recurrence", "interval_minutes", "at_time", "options")


def compute_options_hash(schedule: Schedule) -> str:
    body = {
        "target_id": schedule.target_id,
        "profile": schedule.profile,
        "recurrence": schedule.recurrence,
        "interval_minutes": schedule.interval_minutes,
        "at_time": schedule.at_time,
        "options": schedule.options or {},
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def next_run_after(schedule: Schedule, after: dt.datetime) -> dt.datetime:
    """First run strictly after ``after`` (UTC-aware)."""
    if after.tzinfo is None:
        after = after.replace(tzinfo=dt.timezone.utc)
    if schedule.recurrence == "INTERVAL":
        step = dt.timedelta(minutes=max(int(schedule.interval_minutes or 60), 15))
        base = schedule.last_run_at or schedule.created_at or after
        if base.tzinfo is None:
            base = base.replace(tzinfo=dt.timezone.utc)
        nxt = base + step
        while nxt <= after:
            nxt += step
        return nxt
    # DAILY at HH:MM in the schedule timezone.
    tz = _tz(schedule.timezone)
    hh, mm = (int(x) for x in (schedule.at_time or "03:00").split(":"))
    local_after = after.astimezone(tz)
    candidate = local_after.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= local_after:
        candidate += dt.timedelta(days=1)
    return candidate.astimezone(dt.timezone.utc)


def tick(db: Session, *, enqueue) -> dict:
    """Advance every due schedule. ``enqueue(execution_id)`` submits work."""
    now = dt.datetime.now(dt.timezone.utc)
    created = skipped = expired = paused = 0

    schedules = db.execute(
        select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None))
    ).scalars().all()

    for sched in schedules:
        due = sched.next_run_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=dt.timezone.utc)
        if due > now:
            continue

        tolerance = dt.timedelta(minutes=max(int(sched.interval_minutes or 1440), 15))
        missed = (now - due) > tolerance

        if db.execute(
            select(ScheduleOccurrence).where(
                ScheduleOccurrence.schedule_id == sched.id,
                ScheduleOccurrence.scheduled_for == due,
            )
        ).scalar_one_or_none() is None:
            occ = ScheduleOccurrence(schedule_id=sched.id, scheduled_for=due, state="PENDING")
            db.add(occ)
            db.flush()

            if missed:
                occ.state = "EXPIRED"
                occ.note = "missed window; not run automatically"
                expired += 1
                AuditService.append(
                    db, actor="system:scheduler", action="SCHEDULE_OCCURRENCE_EXPIRED",
                    object_type="schedule", object_id=sched.id,
                    payload={"scheduled_for": due.isoformat()},
                )
            elif _has_open_occurrence(db, sched, exclude=occ.id) and sched.overlap_policy == "SKIP":
                occ.state = "SKIPPED"
                occ.note = "previous occurrence still active"
                skipped += 1
            elif sched.classification == "PASSIVE":
                execution = ScanExecution(
                    target_id=sched.target_id, requested_by_id=sched.created_by_id,
                    schedule_id=sched.id, profile=sched.profile, classification="PASSIVE",
                    state="QUEUED", queued_at=now, options=sched.options or {},
                )
                db.add(execution)
                db.flush()
                occ.state = "RUNNING"
                occ.execution_id = execution.id
                created += 1
                AuditService.append(
                    db, actor="system:scheduler", action="SCAN_STATE_CHANGE",
                    object_type="scan_execution", object_id=execution.id,
                    payload={"from": "DRAFT", "to": "QUEUED", "via": "schedule"},
                )
                db.commit()
                enqueue(execution.id)
            elif compute_options_hash(sched) != (sched.options_hash or ""):
                # Attestation-relevant fields changed since attestation (PRD 8.2).
                occ.state = "DENIED"
                occ.note = "stored attestation invalidated by a configuration change"
                AuditService.append(
                    db, actor="system:scheduler", action="SCHEDULE_ATTESTATION_INVALIDATED",
                    object_type="schedule", object_id=sched.id, payload={},
                )
            else:  # ACTIVE — never auto-run; create a fresh approval request (PRD 8.2)
                execution = ScanExecution(
                    target_id=sched.target_id, requested_by_id=sched.created_by_id,
                    schedule_id=sched.id, profile=sched.profile, classification="ACTIVE",
                    state="DRAFT", options=sched.options or {},
                )
                db.add(execution)
                db.flush()
                execution.state = "AWAITING_APPROVAL"
                approval = ScanApproval(
                    execution_id=execution.id, target_id=sched.target_id,
                    requested_by_id=sched.created_by_id, schedule_id=sched.id,
                    occurrence_id=occ.id, profile=sched.profile,
                    attestation_text=sched.attestation_text or "(scheduled attestation)",
                    requested_options=sched.options or {}, scope_at_request={},
                    state="AWAITING_APPROVAL",
                )
                db.add(approval)
                occ.state = "AWAITING_APPROVAL"
                occ.execution_id = execution.id
                occ.note = "active occurrence paused pending administrator approval"
                paused += 1
                AuditService.append(
                    db, actor="system:scheduler", action="APPROVAL_REQUESTED",
                    object_type="scan_approval", object_id=approval.id,
                    payload={"execution_id": execution.id, "via": "schedule", "schedule_id": sched.id},
                )
                for admin in db.execute(
                    select(User).where(User.role == "ADMINISTRATOR")
                ).scalars():
                    db.add(Notification(
                        user_id=admin.id, kind="SCHEDULE_APPROVAL_PENDING",
                        title="Scheduled active scan awaiting approval",
                        body=f"Schedule for target {sched.target_id[:8]} has a pending occurrence.",
                    ))

        sched.last_run_at = due
        sched.next_run_at = next_run_after(sched, now)

    db.commit()
    return {"created": created, "skipped": skipped, "expired": expired, "paused": paused}


def _has_open_occurrence(db: Session, sched: Schedule, exclude: str) -> bool:
    rows = db.execute(
        select(ScheduleOccurrence).where(
            ScheduleOccurrence.schedule_id == sched.id,
            ScheduleOccurrence.id != exclude,
            ScheduleOccurrence.state.in_(("PENDING", "RUNNING", "AWAITING_APPROVAL")),
        )
    ).scalars().all()
    for occ in rows:
        if not occ.execution_id:
            return True
        ex = db.get(ScanExecution, occ.execution_id)
        if ex is None or ex.state not in TERMINAL:
            return True
    return False
