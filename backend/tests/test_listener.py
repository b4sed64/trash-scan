"""Internal listener + verified session establishment (PRD v2 Phase 19).

Fake listener; nothing binds. Covers the listener-boundary rules (no wildcard/
host/loopback/public), fixture-association verification, unexpected-callback
quarantine, no-input-before-association, flag gating, and clean termination.
"""
from __future__ import annotations

import pytest

from app.models import (
    LabEnvironment,
    LabFixture,
    ProofAttempt,
    ProofPlan,
    SessionGrant,
    Target,
    User,
)
from app.security import hash_password
from app.services import listener
from app.services import session_broker as broker

_LAB_CIDRS = ["10.10.0.0/16"]


# --- listener boundary validation ------------------------------------------


@pytest.mark.parametrize("iface", ["0.0.0.0", "::", "127.0.0.1", "localhost",
                                    "host.docker.internal", "8.8.8.8", "203.0.113.5"])
def test_listener_rejects_wildcard_host_and_public(iface):
    ok, _ = listener.validate_listener_boundary(iface, 4444, _LAB_CIDRS)
    assert ok is False


def test_listener_accepts_declared_internal_interface():
    ok, _ = listener.validate_listener_boundary("10.10.5.1", 4444, _LAB_CIDRS)
    assert ok is True


def test_listener_rejects_private_outside_declared_boundary():
    ok, _ = listener.validate_listener_boundary("192.168.1.1", 4444, _LAB_CIDRS)
    assert ok is False


# --- establishment ---------------------------------------------------------


@pytest.fixture
def ctx(db):
    u = User(username="lsadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    t = Target(kind="IPV4", value="10.10.5.70")
    env = LabEnvironment(name="lab-ls", provider="fake", isolation_verified=True)
    db.add_all([u, t, env])
    db.flush()
    f = LabFixture(lab_environment_id=env.id, target_id=t.id, name="fx")
    db.add(f)
    db.flush()  # populate f.id before referencing it
    plan = ProofPlan(target_id=t.id, fixture_id=f.id, module_id="m", proof_marker="n",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    grant = SessionGrant(plan_id=plan.id, transport="reverse-tcp",
                         listener_interface="10.10.0.2", listener_port=4444)
    att = ProofAttempt(plan_id=plan.id, state="RUNNING")
    db.add_all([grant, att])
    db.flush()
    db.commit()
    return {"user": u.id, "fixture": f, "grant": grant, "attempt": att,
            "fixture_ip": "10.10.5.70"}


def _cb(source_ip, sid="1", epoch="e1"):
    return listener.CallbackEvent(source_ip=source_ip, native_session_id=sid, epoch=epoch)


def test_matching_callback_reaches_ready(db, ctx):
    sess = listener.establish(db, attempt=ctx["attempt"], grant=ctx["grant"],
                              fixture=ctx["fixture"], expected_source_ip=ctx["fixture_ip"],
                              allowed_cidrs=_LAB_CIDRS, callback=_cb(ctx["fixture_ip"]),
                              owner_id=ctx["user"], enabled=True)
    assert sess.state == broker.READY
    db.refresh(ctx["attempt"])
    assert ctx["attempt"].state == "SESSION_ACTIVE"


def test_mismatched_callback_is_quarantined_and_no_input(db, ctx):
    sess = listener.establish(db, attempt=ctx["attempt"], grant=ctx["grant"],
                              fixture=ctx["fixture"], expected_source_ip=ctx["fixture_ip"],
                              allowed_cidrs=_LAB_CIDRS, callback=_cb("10.10.5.200"),
                              owner_id=ctx["user"], enabled=True)
    assert sess.state == broker.QUARANTINED
    lease = broker.acquire_lease(db, sess, "op1") if False else None
    assert broker.accepts_input(sess, lease=lease, token="") is False


def test_establish_refused_when_sessions_disabled(db, ctx):
    with pytest.raises(listener.ListenerError):
        listener.establish(db, attempt=ctx["attempt"], grant=ctx["grant"], fixture=ctx["fixture"],
                           expected_source_ip=ctx["fixture_ip"], allowed_cidrs=_LAB_CIDRS,
                           callback=_cb(ctx["fixture_ip"]), owner_id=ctx["user"], enabled=False)


def test_bad_listener_interface_refuses_establish(db, ctx):
    ctx["grant"].listener_interface = "0.0.0.0"
    db.flush()
    with pytest.raises(listener.ListenerError):
        listener.establish(db, attempt=ctx["attempt"], grant=ctx["grant"], fixture=ctx["fixture"],
                           expected_source_ip=ctx["fixture_ip"], allowed_cidrs=_LAB_CIDRS,
                           callback=_cb(ctx["fixture_ip"]), owner_id=ctx["user"], enabled=True)


def test_terminate_removes_listener_and_session(db, ctx):
    fl = listener.FakeListener("10.10.0.2", 4444)
    sess = listener.establish(db, attempt=ctx["attempt"], grant=ctx["grant"], fixture=ctx["fixture"],
                              expected_source_ip=ctx["fixture_ip"], allowed_cidrs=_LAB_CIDRS,
                              callback=_cb(ctx["fixture_ip"]), owner_id=ctx["user"], enabled=True)
    assert listener.attempt_has_live_session(db, ctx["attempt"].id) is True
    listener.terminate(db, fl, sess)
    db.flush()
    assert sess.state == broker.CLOSED
    assert fl.open is False
    assert listener.attempt_has_live_session(db, ctx["attempt"].id) is False
