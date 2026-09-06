"""Passive schedule evaluation (PRD §8.2, §11.5)."""
from __future__ import annotations

import datetime as dt

import pytest

from app.models import ScanExecution, Schedule, ScheduleOccurrence, Target, User
from app.security import hash_password
from app.services.schedule_service import next_run_after, tick


@pytest.fixture
def lab(db):
    u = User(username="s", role="SCANNER", password_hash=hash_password("x" * 12), is_active=True)
    t = Target(kind="DOMAIN", value="lab.example.com")
    db.add_all([u, t])
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def _schedule(db, target, user, **kw) -> Schedule:
    now = dt.datetime.now(dt.timezone.utc)
    defaults = dict(
        target_id=target, created_by_id=user, profile="PASSIVE", classification="PASSIVE",
        recurrence="INTERVAL", interval_minutes=30, timezone="UTC", enabled=True,
        overlap_policy="SKIP", options={}, created_at=now - dt.timedelta(hours=2),
        last_run_at=now - dt.timedelta(hours=1),
    )
    defaults.update(kw)
    s = Schedule(**defaults)
    s.next_run_at = defaults.get("next_run_at") or (now - dt.timedelta(minutes=1))
    db.add(s)
    db.commit()
    return s


def test_due_passive_schedule_creates_execution(db, lab):
    s = _schedule(db, lab["target"], lab["user"])
    enqueued = []
    result = tick(db, enqueue=enqueued.append)
    assert result["created"] == 1
    assert len(enqueued) == 1

    occ = db.query(ScheduleOccurrence).filter(ScheduleOccurrence.schedule_id == s.id).one()
    assert occ.state == "RUNNING"
    ex = db.get(ScanExecution, occ.execution_id)
    assert ex.state == "QUEUED" and ex.classification == "PASSIVE"
    db.refresh(s)
    nxt = s.next_run_at
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=dt.timezone.utc)
    assert nxt > dt.datetime.now(dt.timezone.utc)


def test_missed_occurrence_is_expired_not_run(db, lab):
    now = dt.datetime.now(dt.timezone.utc)
    s = _schedule(db, lab["target"], lab["user"],
                  next_run_at=now - dt.timedelta(hours=5),
                  last_run_at=now - dt.timedelta(hours=6))
    result = tick(db, enqueue=lambda _e: None)
    assert result["expired"] == 1 and result["created"] == 0
    occ = db.query(ScheduleOccurrence).filter(ScheduleOccurrence.schedule_id == s.id).one()
    assert occ.state == "EXPIRED"
    assert occ.execution_id is None


def test_overlap_skip_when_previous_still_running(db, lab):
    s = _schedule(db, lab["target"], lab["user"])
    # a still-running prior occurrence
    prior_ex = ScanExecution(target_id=lab["target"], profile="PASSIVE", classification="PASSIVE",
                             state="RUNNING")
    db.add(prior_ex)
    db.flush()
    db.add(ScheduleOccurrence(
        schedule_id=s.id, scheduled_for=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=45),
        state="RUNNING", execution_id=prior_ex.id,
    ))
    db.commit()

    result = tick(db, enqueue=lambda _e: None)
    assert result["skipped"] == 1
    states = {o.state for o in db.query(ScheduleOccurrence).filter(
        ScheduleOccurrence.schedule_id == s.id)}
    assert "SKIPPED" in states


def test_next_run_after_interval_advances_past_now(db, lab):
    s = _schedule(db, lab["target"], lab["user"], interval_minutes=15)
    nxt = next_run_after(s, dt.datetime.now(dt.timezone.utc))
    assert nxt > dt.datetime.now(dt.timezone.utc)
