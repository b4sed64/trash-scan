"""Session domain + broker on fakes (PRD v2 Phase 18).

Fake-only; no real listener/target. Covers the safety invariants: unverified
sessions accept no input, ambiguous second sessions are quarantined, native-ID
reuse across framework epochs stays distinct, single-writer leases, and admin
takeover fencing out the old writer.
"""
from __future__ import annotations

import pytest

from app.models import ProofAttempt, ProofPlan, Target, User
from app.security import hash_password
from app.services import session_broker as sb


@pytest.fixture
def ctx(db):
    u = User(username="sbadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    t = Target(kind="IPV4", value="10.10.9.30")
    db.add_all([u, t])
    db.flush()
    plan = ProofPlan(target_id=t.id, fixture_id="fx", module_id="m", proof_marker="n",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    att = ProofAttempt(plan_id=plan.id, state="SESSION_ACTIVE")
    db.add(att)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id, "attempt": att.id}


def _establish(db, ctx, **kw):
    base = dict(attempt_id=ctx["attempt"], grant_id=None, fixture_id="fx", target_id=ctx["target"],
                framework_epoch="epoch-1", native_session_id="1", transport="reverse-tcp",
                observed_connection="10.10.9.30:4444", owner_id=ctx["user"])
    base.update(kw)
    return sb.establish(db, **base)


# --- verification + input gating -------------------------------------------


def test_unverified_session_accepts_no_input(db, ctx):
    s = _establish(db, ctx)
    assert s.state == sb.ESTABLISHED_UNVERIFIED
    lease = sb.acquire_lease(db, s, "op1")  # even with a lease, unverified blocks input
    assert sb.accepts_input(s, lease=lease, token=lease.fencing_token) is False


def test_verify_requires_fixture_association(db, ctx):
    s = _establish(db, ctx)
    assert sb.verify(db, s, fixture_association_ok=False) == sb.QUARANTINED
    s2 = _establish(db, ctx, native_session_id="2")
    # s2 is a second session for the attempt -> quarantined on establish
    assert s2.state == sb.QUARANTINED


def test_ready_session_with_lease_accepts_input_observer_does_not(db, ctx):
    s = _establish(db, ctx)
    sb.verify(db, s, fixture_association_ok=True)
    lease = sb.acquire_lease(db, s, "op1")
    assert sb.accepts_input(s, lease=lease, token=lease.fencing_token) is True
    # an observer with no lease / wrong token cannot write
    assert sb.accepts_input(s, lease=lease, token="wrong") is False
    assert sb.accepts_input(s, lease=None, token="") is False


# --- native id reuse / identity --------------------------------------------


def test_native_id_reuse_across_epochs_is_distinct(db, ctx):
    s1 = _establish(db, ctx, framework_epoch="epoch-1", native_session_id="7")
    sb.verify(db, s1, fixture_association_ok=True)
    sb.disconnect(db, s1)
    s1.state = sb.CLOSED
    db.flush()
    # a framework restart reuses native id "7" under a new epoch -> a new product id
    s2 = _establish(db, ctx, framework_epoch="epoch-2", native_session_id="7")
    assert s2.id != s1.id
    assert s2.framework_epoch != s1.framework_epoch


# --- single-writer lease + takeover ----------------------------------------


def test_single_writer_lease_and_takeover_fences_old(db, ctx):
    s = _establish(db, ctx)
    sb.verify(db, s, fixture_association_ok=True)
    lease1 = sb.acquire_lease(db, s, "op1")
    # a second operator cannot grab control without takeover
    with pytest.raises(sb.SessionError):
        sb.acquire_lease(db, s, "op2")
    # admin takeover issues a new token and fences op1 out
    lease2 = sb.acquire_lease(db, s, "admin", takeover=True)
    assert lease2.fencing_token != lease1.fencing_token
    assert sb.accepts_input(s, lease=lease1, token=lease1.fencing_token) is False
    assert sb.accepts_input(s, lease=lease2, token=lease2.fencing_token) is True


def test_disconnect_stops_input(db, ctx):
    s = _establish(db, ctx)
    sb.verify(db, s, fixture_association_ok=True)
    lease = sb.acquire_lease(db, s, "op1")
    sb.disconnect(db, s)
    # the lease is released; the old token no longer authorizes input
    assert sb.accepts_input(s, lease=lease, token=lease.fencing_token) is False
