"""Guided session actions — predefined, fake-backed (PRD v2 Phase 20).

Covers: in-grant dispatch completes, out-of-grant rejected, no/invalid lease
rejected, idempotent request_id, per-session budget, unknown-outcome not
auto-resent, unknown action rejected, and terminate closing the session.
"""
from __future__ import annotations

import pytest

from app.models import (
    InteractionRecord,
    LabSession,
    ProofAttempt,
    ProofPlan,
    SessionGrant,
    Target,
    User,
)
from app.security import hash_password
from app.services import guided
from app.services import session_broker as broker


@pytest.fixture(autouse=True)
def _reset_runner():
    yield
    guided.set_runner(None)


@pytest.fixture
def sess(db):
    u = User(username="gdadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    t = Target(kind="IPV4", value="10.10.9.40")
    db.add_all([u, t])
    db.flush()
    plan = ProofPlan(target_id=t.id, fixture_id="fx", module_id="m", proof_marker="n",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    grant = SessionGrant(plan_id=plan.id, transport="reverse-tcp",
                         guided_action_ids=["whoami", "read-marker", "terminate"])
    att = ProofAttempt(plan_id=plan.id, state="SESSION_ACTIVE")
    db.add_all([grant, att])
    db.flush()
    s = LabSession(attempt_id=att.id, grant_id=grant.id, fixture_id="fx", target_id=t.id,
                   state=broker.READY)
    db.add(s)
    db.flush()
    db.commit()
    return {"session": s, "grant": grant, "user": u.id}


def _lease(db, s):
    return broker.acquire_lease(db, s, "op1")


def _dispatch(db, sess, action_id, params=None, request_id="r1", token=None, lease=None):
    lease = lease or _lease(db, sess["session"])
    return guided.dispatch(db, session=sess["session"], grant=sess["grant"], action_id=action_id,
                           params=params or {}, lease=lease, token=token or lease.fencing_token,
                           request_id=request_id, enabled=True)


def test_in_grant_action_completes(db, sess):
    rec = _dispatch(db, sess, "whoami")
    assert rec.state == "COMPLETED"
    assert "lab-fixture-user" in rec.output


def test_out_of_grant_action_rejected(db, sess):
    rec = _dispatch(db, sess, "os-context")  # not in the grant's action ids
    assert rec.state == "REJECTED"
    assert "not in grant" in rec.reason


def test_unknown_action_rejected(db, sess):
    rec = _dispatch(db, sess, "rm-rf")
    assert rec.state == "REJECTED"


def test_dispatch_requires_valid_lease(db, sess):
    lease = _lease(db, sess["session"])
    rec = guided.dispatch(db, session=sess["session"], grant=sess["grant"], action_id="whoami",
                          params={}, lease=lease, token="WRONG", request_id="rx", enabled=True)
    assert rec.state == "REJECTED"


def test_idempotent_request_id(db, sess):
    lease = _lease(db, sess["session"])
    r1 = _dispatch(db, sess, "whoami", request_id="same", lease=lease)
    r2 = _dispatch(db, sess, "whoami", request_id="same", lease=lease)
    assert r1.id == r2.id  # duplicate submit -> one record


def test_required_param_validation(db, sess):
    rec = _dispatch(db, sess, "read-marker", params={})  # missing 'marker'
    assert rec.state == "REJECTED"
    ok = _dispatch(db, sess, "read-marker", params={"marker": "abc"}, request_id="r2")
    assert ok.state == "COMPLETED" and "abc" in ok.output


def test_unknown_outcome_not_auto_resent(db, sess):
    guided.set_runner(lambda a, s, p: (_ for _ in ()).throw(guided.DispatchTimeout()))
    rec = _dispatch(db, sess, "whoami", request_id="to1")
    assert rec.state == "OUTCOME_UNKNOWN"
    # a resend with the same request id returns the same record, never re-dispatches
    rec2 = _dispatch(db, sess, "whoami", request_id="to1")
    assert rec2.id == rec.id and rec2.state == "OUTCOME_UNKNOWN"


def test_budget_exceeded_rejected(db, sess, monkeypatch):
    monkeypatch.setattr(guided, "TOTAL_INVOCATION_LIMIT", 2)
    lease = _lease(db, sess["session"])
    _dispatch(db, sess, "whoami", request_id="a", lease=lease)
    _dispatch(db, sess, "whoami", request_id="b", lease=lease)
    over = _dispatch(db, sess, "whoami", request_id="c", lease=lease)
    assert over.state == "REJECTED" and "budget" in over.reason


def test_terminate_closes_session(db, sess):
    rec = _dispatch(db, sess, "terminate")
    assert rec.state == "COMPLETED"
    assert sess["session"].state == broker.CLOSED
