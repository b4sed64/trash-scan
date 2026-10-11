"""Approved one-shot proof execution (PRD v2 Phase 16).

Fake-backed. The central guarantees: execution is BLOCKED whenever the lab-proof
flag is off or the fixture is not ready; a plan is one-shot; DEMONSTRATED needs
the per-attempt marker echoed + a negative control (never a bare framework
success); and proof vs recovery outcomes are independent.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from app.models import (
    LabEnvironment,
    LabFixture,
    PrivateCidr,
    ProofPlan,
    Target,
    User,
)
from app.security import hash_password
from app.services import exploitability, lab, proof
from app.services.framework import FakeFrameworkAdapter, NativeResult, SAFE, VULNERABLE

_MODULE = {
    "module_id": "sample/http-exposed-config-read",
    "admission_state": "ADMITTED",
    "issue_types": ["nuclei:trashscan-git-config-exposure"],
    "claim": "reads a seeded marker", "check_classification": "active-read-only",
    "expected_effect": "reads one marker; exits",
    "typed_inputs": {}, "prerequisites": [],
}


@pytest.fixture(autouse=True)
def _registry():
    exploitability.set_registry({"modules": [_MODULE]})
    yield
    exploitability.set_registry(None)
    proof.set_framework_adapter(None)


@pytest.fixture
def lab_ctx(db):
    admin = User(username="pfadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    db.add_all([admin, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.9.10")
    env = LabEnvironment(name="lab-p", provider="fake")
    db.add_all([t, env])
    db.flush()
    f = LabFixture(lab_environment_id=env.id, target_id=t.id, name="fx", build_id="b1")
    db.add(f)
    db.flush()
    db.commit()
    return {"admin": db.get(User, admin.id), "target": t.id, "env": env, "fixture": f}


def _plan(db, ctx) -> ProofPlan:
    plan = proof.create_plan(db, target_id=ctx["target"], fixture=ctx["fixture"],
                             module_id=_MODULE["module_id"], options={},
                             operator_id=ctx["admin"].id, engagement_ref="ENG-1")
    proof.approve_plan(db, plan, admin=ctx["admin"], attestation=proof.PROOF_ATTESTATION)
    db.commit()
    return plan


def _make_ready(db, ctx):
    ctrl = lab.FakeLabController(isolation_ok=True, health=lab.HEALTHY, restore_ok=True)
    lab.verify_isolation(db, ctx["env"], ctrl)
    lab.rehearse_restore(db, ctx["fixture"], ctrl, ctx["admin"].id)
    db.commit()


def _settings_flag(on: bool):
    # minimal settings stand-in used by proof._gate / get_settings
    return SimpleNamespace(enable_lab_proof=on)


# --- gating ----------------------------------------------------------------


def test_blocked_when_flag_off(db, lab_ctx, monkeypatch):
    plan = _plan(db, lab_ctx)
    _make_ready(db, lab_ctx)  # even ready, the flag is off by default
    monkeypatch.setattr(proof, "get_settings", lambda: _settings_flag(False))
    attempt = proof.execute(db, plan)
    db.commit()
    assert attempt.state == "BLOCKED"
    assert attempt.proof_outcome == proof.BLOCKED
    assert "disabled" in attempt.blocked_reason


def test_blocked_when_fixture_not_ready(db, lab_ctx, monkeypatch):
    plan = _plan(db, lab_ctx)  # fixture never made ready
    monkeypatch.setattr(proof, "get_settings", lambda: _settings_flag(True))
    attempt = proof.execute(db, plan)
    db.commit()
    assert attempt.state == "BLOCKED"
    assert "not proof-ready" in attempt.blocked_reason


# --- execution (gates opened only in-test) ---------------------------------


def test_demonstrated_requires_marker_echo_and_negative_control(db, lab_ctx, monkeypatch):
    plan = _plan(db, lab_ctx)
    _make_ready(db, lab_ctx)
    monkeypatch.setattr(proof, "get_settings", lambda: _settings_flag(True))
    # fake adapter echoes the exact per-attempt marker + passes negative control
    proof.set_framework_adapter(FakeFrameworkAdapter(fixtures={
        _MODULE["module_id"]: NativeResult(job_id="", native_code=VULNERABLE,
                                           raw={"marker": plan.proof_marker,
                                                "negative_control_passed": True},
                                           service_reached=True, check_completed=True)}))
    attempt = proof.execute(db, plan)
    db.commit()
    assert attempt.proof_outcome == proof.DEMONSTRATED
    assert attempt.recovery_outcome == lab.RESTORED_VERIFIED  # independent dimension
    db.refresh(plan)
    assert plan.state == "CONSUMED"


def test_bare_success_without_marker_is_not_demonstrated(db, lab_ctx, monkeypatch):
    plan = _plan(db, lab_ctx)
    _make_ready(db, lab_ctx)
    monkeypatch.setattr(proof, "get_settings", lambda: _settings_flag(True))
    proof.set_framework_adapter(FakeFrameworkAdapter(fixtures={
        _MODULE["module_id"]: NativeResult(job_id="", native_code=VULNERABLE,
                                           raw={"marker": "WRONG", "negative_control_passed": True},
                                           service_reached=True, check_completed=True)}))
    attempt = proof.execute(db, plan)
    db.commit()
    assert attempt.proof_outcome == proof.ATTEMPTED_NOT_DEMONSTRATED


def test_plan_is_one_shot(db, lab_ctx, monkeypatch):
    plan = _plan(db, lab_ctx)
    _make_ready(db, lab_ctx)
    monkeypatch.setattr(proof, "get_settings", lambda: _settings_flag(True))
    proof.set_framework_adapter(FakeFrameworkAdapter(fixtures={
        _MODULE["module_id"]: NativeResult(job_id="", native_code=SAFE,
                                           service_reached=True, check_completed=True)}))
    proof.execute(db, plan)
    db.commit()
    # second execution is refused — the plan was consumed
    attempt2 = proof.execute(db, plan)
    db.commit()
    assert attempt2.state == "BLOCKED"
    assert "consumed" in attempt2.blocked_reason


def test_approval_requires_exact_attestation(db, lab_ctx):
    plan = proof.create_plan(db, target_id=lab_ctx["target"], fixture=lab_ctx["fixture"],
                             module_id=_MODULE["module_id"], options={},
                             operator_id=lab_ctx["admin"].id, engagement_ref="E")
    with pytest.raises(proof.ProofError):
        proof.approve_plan(db, plan, admin=lab_ctx["admin"], attestation="nope")


def test_unadmitted_module_cannot_be_planned(db, lab_ctx):
    with pytest.raises(proof.ProofError):
        proof.create_plan(db, target_id=lab_ctx["target"], fixture=lab_ctx["fixture"],
                          module_id="research/not-admitted", options={},
                          operator_id=lab_ctx["admin"].id, engagement_ref="E")
