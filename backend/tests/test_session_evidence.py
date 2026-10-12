"""Session transcripts, evidence and recovery reporting (PRD v2 Phase 21).

Covers: the three evidence kinds stay separate (only PROOF_EFFECT can be
demonstrated), the session report distinguishes demonstrated-effect / state /
transcript-gaps / recovery, absolute + idle expiry, and restart reconciliation
marking an orphaned session LOST without releasing the fixture lock.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.models import (
    LabFixture,
    LabSession,
    ProofAttempt,
    ProofPlan,
    RecoveryRecord,
    StreamEvent,
    Target,
    User,
)
from app.security import hash_password
from app.services import session_broker as broker
from app.services import session_evidence as se


@pytest.fixture
def ctx(db):
    u = User(username="seadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    t = Target(kind="IPV4", value="10.10.9.50")
    db.add_all([u, t])
    db.flush()
    plan = ProofPlan(target_id=t.id, fixture_id="fx", module_id="m", proof_marker="n",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    att = ProofAttempt(plan_id=plan.id, state="SESSION_ACTIVE")
    db.add(att)
    db.flush()
    s = LabSession(attempt_id=att.id, fixture_id="fx", target_id=t.id, state=broker.READY,
                   expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=600))
    db.add(s)
    db.flush()
    db.commit()
    return {"target": t.id, "attempt": att, "session": s}


# --- evidence kinds stay separate ------------------------------------------


def test_only_proof_effect_can_be_demonstrated(db, ctx):
    opened = se.capture(db, ctx["session"].id, se.SESSION_OPENED, demonstrated=True)
    output = se.capture(db, ctx["session"].id, se.COMMAND_OUTPUT, demonstrated=True)
    proof = se.capture(db, ctx["session"].id, se.PROOF_EFFECT, demonstrated=True)
    # a session-opened / command-output event can never claim demonstrated impact
    assert opened.demonstrated is False
    assert output.demonstrated is False
    assert proof.demonstrated is True


def test_session_report_separates_dimensions(db, ctx):
    se.capture(db, ctx["session"].id, se.SESSION_OPENED)
    se.capture(db, ctx["session"].id, se.COMMAND_OUTPUT, effect_claim="whoami")
    db.add(StreamEvent(attempt_id=ctx["attempt"].id, seq=1, event_type="GAP", payload="gap"))
    db.add(RecoveryRecord(fixture_id="fx", outcome="RECOVERY_FAILED", detail="restore failed"))
    db.flush()
    rep = se.session_report(db, ctx["session"])
    assert rep["demonstrated_effect"] is False
    assert rep["session_state"] == broker.READY
    assert rep["transcript_gaps"] == 1
    assert any(r["outcome"] == "RECOVERY_FAILED" for r in rep["recovery_incidents"])
    assert len(rep["evidence"]) == 2


# --- expiry + reconciliation -----------------------------------------------


def test_absolute_and_idle_expiry(db, ctx):
    s = ctx["session"]
    s.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    assert broker.absolute_expired(s) is True
    last = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=200)
    assert broker.idle_expired(s, last, idle_seconds=120) is True
    recent = dt.datetime.now(dt.timezone.utc)
    assert broker.idle_expired(s, recent, idle_seconds=120) is False


def test_reconcile_marks_orphan_lost_but_keeps_fixture_lock(db, ctx):
    # a real fixture, locked by the attempt; the attempt then goes terminal
    env_fixture = LabFixture(lab_environment_id="env", target_id=ctx["target"], name="fx",
                             locked_by="attempt:x")
    db.add(env_fixture)
    ctx["attempt"].state = "COMPLETED"  # parent terminal -> session is orphaned
    db.flush()
    n = broker.reconcile_sessions(db)
    assert n == 1
    db.refresh(ctx["session"])
    assert ctx["session"].state == broker.LOST
    # the fixture lock is NOT released by reconciliation (held until recovery)
    db.refresh(env_fixture)
    assert env_fixture.locked_by == "attempt:x"
