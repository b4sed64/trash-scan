"""Administrator target-session terminal — fake channel (PRD v2 Phase 22).

Covers: grant requires the exact attestation and a verified session; input is
refused without an active grant, when the frame exceeds 4 KiB, or without a valid
lease; duplicate frames are deduplicated (no input replay); capabilities disclose
no-PTY; a rejected frame still records a receipt.
"""
from __future__ import annotations

import pytest

from app.models import (
    LabSession,
    ProofAttempt,
    ProofPlan,
    Target,
    TerminalFrameReceipt,
    User,
)
from app.security import hash_password
from app.services import session_broker as broker
from app.services import terminal


@pytest.fixture
def ctx(db):
    admin = User(username="tmadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    t = Target(kind="IPV4", value="10.10.9.60")
    db.add_all([admin, t])
    db.flush()
    plan = ProofPlan(target_id=t.id, fixture_id="fx", module_id="m", proof_marker="n",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    att = ProofAttempt(plan_id=plan.id, state="SESSION_ACTIVE")
    db.add(att)
    db.flush()
    s = LabSession(attempt_id=att.id, fixture_id="fx", target_id=t.id, state=broker.READY)
    db.add(s)
    db.flush()
    db.commit()
    return {"admin": db.get(User, admin.id), "session": s}


def _grant(db, ctx):
    return terminal.grant_terminal(db, session=ctx["session"], admin=ctx["admin"],
                                   attestation=terminal.TERMINAL_ATTESTATION,
                                   allowed_seconds=600, enabled=True)


def _lease(db, ctx):
    return broker.acquire_lease(db, ctx["session"], "admin")


# --- grant -----------------------------------------------------------------


def test_grant_requires_exact_attestation(db, ctx):
    with pytest.raises(terminal.TerminalError):
        terminal.grant_terminal(db, session=ctx["session"], admin=ctx["admin"],
                                attestation="nope", allowed_seconds=600, enabled=True)


def test_grant_requires_enabled_flag(db, ctx):
    with pytest.raises(terminal.TerminalError):
        terminal.grant_terminal(db, session=ctx["session"], admin=ctx["admin"],
                                attestation=terminal.TERMINAL_ATTESTATION, allowed_seconds=600,
                                enabled=False)


def test_capabilities_disclose_no_pty():
    caps = terminal.capabilities()
    assert caps["pty"] is False and caps["mode"] == "command-output"
    assert caps["max_input_bytes"] == terminal.MAX_FRAME_BYTES


# --- input frames ----------------------------------------------------------


def test_accepted_frame_with_grant_and_lease(db, ctx):
    grant = _grant(db, ctx)
    lease = _lease(db, ctx)
    r = terminal.submit_frame(db, session=ctx["session"], grant=grant, lease=lease,
                              token=lease.fencing_token, input_text="id", request_id="r1",
                              enabled=True)
    assert r.accepted is True


def test_input_refused_without_grant(db, ctx):
    lease = _lease(db, ctx)
    r = terminal.submit_frame(db, session=ctx["session"], grant=None, lease=lease,
                              token=lease.fencing_token, input_text="id", request_id="r1",
                              enabled=True)
    assert r.accepted is False and "no active terminal grant" in r.reason


def test_input_refused_without_valid_lease(db, ctx):
    grant = _grant(db, ctx)
    r = terminal.submit_frame(db, session=ctx["session"], grant=grant, lease=None, token="",
                              input_text="id", request_id="r1", enabled=True)
    assert r.accepted is False


def test_oversize_frame_rejected_but_recorded(db, ctx):
    grant = _grant(db, ctx)
    lease = _lease(db, ctx)
    big = "A" * (terminal.MAX_FRAME_BYTES + 1)
    r = terminal.submit_frame(db, session=ctx["session"], grant=grant, lease=lease,
                              token=lease.fencing_token, input_text=big, request_id="r1",
                              enabled=True)
    assert r.accepted is False and "exceeds" in r.reason
    # the rejected frame is still recorded for accountability
    assert db.query(TerminalFrameReceipt).filter(
        TerminalFrameReceipt.session_id == ctx["session"].id).count() == 1


def test_duplicate_request_id_does_not_replay(db, ctx):
    grant = _grant(db, ctx)
    lease = _lease(db, ctx)
    r1 = terminal.submit_frame(db, session=ctx["session"], grant=grant, lease=lease,
                               token=lease.fencing_token, input_text="id", request_id="dup",
                               enabled=True)
    r2 = terminal.submit_frame(db, session=ctx["session"], grant=grant, lease=lease,
                               token=lease.fencing_token, input_text="id", request_id="dup",
                               enabled=True)
    assert r1.id == r2.id
    assert db.query(TerminalFrameReceipt).filter(
        TerminalFrameReceipt.session_id == ctx["session"].id).count() == 1
