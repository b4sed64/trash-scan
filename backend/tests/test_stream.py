"""Live execution workspace streaming — durable events + sanitization (Phase 17).

Fake streams, no target traffic. Covers output sanitization (ANSI/control/HTML),
monotonic ordering, reconnect-cursor replay, gap surfacing, the bounded
transcript, and that a proof attempt emits durable status/output/evidence events.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.models import ProofAttempt, ProofPlan, StreamEvent, Target, User
from app.security import hash_password
from app.services import stream


@pytest.fixture
def attempt(db):
    u = User(username="stadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    t = Target(kind="IPV4", value="10.10.9.20")
    db.add_all([u, t])
    db.flush()
    plan = ProofPlan(target_id=t.id, fixture_id="fx", module_id="m", proof_marker="nonce-x",
                     plan_hash="h", state="CONSUMED")
    db.add(plan)
    db.flush()
    a = ProofAttempt(plan_id=plan.id, state="RUNNING")
    db.add(a)
    db.flush()
    db.commit()
    return a


# --- sanitization ----------------------------------------------------------


def test_sanitize_strips_ansi_control_and_escapes_html():
    raw = "\x1b[31mred\x1b[0m <script>alert(1)</script>\x07\x00 ok"
    out = stream.sanitize_output(raw)
    assert "\x1b" not in out and "\x07" not in out and "\x00" not in out
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "red" in out and "ok" in out


def test_output_payload_is_bounded():
    out = stream.sanitize_output("A" * 100000)
    assert len(out) <= stream.MAX_PAYLOAD


# --- ordering, cursor, gaps -------------------------------------------------


def test_monotonic_seq_and_cursor_replay(db, attempt):
    stream.append_status(db, attempt.id, "RUNNING")
    stream.append_output(db, attempt.id, "line 1")
    stream.append_output(db, attempt.id, "line 2")
    db.commit()
    seqs = [e["seq"] for e in stream.events_after(db, attempt.id, 0)]
    assert seqs == sorted(seqs) and len(seqs) == 3
    # reconnect after the first event returns only the newer two
    after_first = stream.events_after(db, attempt.id, seqs[0])
    assert [e["seq"] for e in after_first] == seqs[1:]
    # a cursor at/after the newest returns nothing
    assert stream.events_after(db, attempt.id, seqs[-1]) == []


def test_output_events_do_not_overwrite_status_truth(db, attempt):
    stream.append_status(db, attempt.id, "RUNNING")
    stream.append_output(db, attempt.id, "noise")
    db.commit()
    # the durable attempt state is unchanged by output events
    db.refresh(attempt)
    assert attempt.state == "RUNNING"
    kinds = {e["type"] for e in stream.events_after(db, attempt.id, 0)}
    assert stream.STATUS in kinds and stream.OUTPUT in kinds


def test_transcript_limit_produces_a_gap(db, attempt, monkeypatch):
    monkeypatch.setattr(stream, "TRANSCRIPT_LIMIT_BYTES", 50)
    monkeypatch.setattr(stream, "MAX_PAYLOAD", 40)
    stream.append_output(db, attempt.id, "A" * 40)
    stream.append_output(db, attempt.id, "B" * 40)  # would exceed 50 -> GAP
    db.commit()
    types = [e["type"] for e in stream.events_after(db, attempt.id, 0)]
    assert stream.GAP in types


# --- end-to-end: a proof attempt emits durable events -----------------------


def test_proof_attempt_emits_durable_events(db):
    # a BLOCKED execution still records status + gap events for the workspace
    from app.services import exploitability, proof
    from app.models import LabEnvironment, LabFixture, PrivateCidr

    exploitability.set_registry({"modules": [{
        "module_id": "sample/m", "admission_state": "ADMITTED",
        "issue_types": [], "prerequisites": [], "typed_inputs": {}}]})
    try:
        u = User(username="pe", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
        t = Target(kind="IPV4", value="10.10.9.21")
        env = LabEnvironment(name="e2e-lab", provider="fake")
        db.add_all([u, t, env, PrivateCidr(cidr="10.10.0.0/16")])
        db.flush()
        fx = LabFixture(lab_environment_id=env.id, target_id=t.id)
        db.add(fx)
        db.flush()
        plan = proof.create_plan(db, target_id=t.id, fixture=fx, module_id="sample/m",
                                 options={}, operator_id=u.id, engagement_ref="E")
        proof.approve_plan(db, plan, admin=u, attestation=proof.PROOF_ATTESTATION)
        db.commit()
        attempt = proof.execute(db, plan)  # BLOCKED (flag off) — still emits events
        db.commit()
        evs = stream.events_after(db, attempt.id, 0)
        assert any(e["type"] == stream.STATUS and e["payload"] == "BLOCKED" for e in evs)
    finally:
        exploitability.set_registry(None)
