"""Approved one-shot proof execution (PRD v2 §21.5-21.7, Phase 16).

Builds the proof plan -> attestation/approval -> single bounded execution ->
evidence -> recovery lifecycle. It is fake-backed (drives the Phase 14
FakeFrameworkAdapter) and defended by hard gates checked at execution time:

  * the ``enable_lab_proof`` feature flag (OFF by default),
  * fixture readiness (verified isolation + restore rehearsal + HEALTHY + lock),
  * a single global active proof, one attempt per plan (one-shot, no retry),
  * the two-hour one-start approval window.

With the flag off and no ready fixture — the state of any non-lab environment —
every execution resolves to BLOCKED before anything runs. DEMONSTRATED requires
the per-attempt marker to be echoed back and a negative control to hold; the
framework merely reporting success is never sufficient.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    LabEnvironment,
    LabFixture,
    ProofAttempt,
    ProofEvidence,
    ProofPlan,
)
from . import lab
from . import stream
from .audit_service import AuditService
from .exploitability import list_modules
from .framework import CheckJob, VULNERABLE, get_framework_adapter, interpret_native_result

PROOF_ATTESTATION = (
    "I confirm this proof runs only against an isolated, recoverable lab fixture "
    "my team owns, and I accept the exact permitted benign effect"
)

# Proof outcomes (§21.7).
DEMONSTRATED = "DEMONSTRATED"
ATTEMPTED_NOT_DEMONSTRATED = "ATTEMPTED_NOT_DEMONSTRATED"
INCONCLUSIVE = "INCONCLUSIVE"
BLOCKED = "BLOCKED"
ERROR = "ERROR"

_ACTIVE_STATES = ("PREFLIGHT", "RUNNING", "STOPPING", "RECOVERING")

# Test seam for the framework adapter (defaults to the fake).
_framework_override = None


def set_framework_adapter(adapter) -> None:
    global _framework_override
    _framework_override = adapter


def _framework():
    return _framework_override if _framework_override is not None else get_framework_adapter()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _module(module_id: str) -> dict | None:
    return next((m for m in list_modules() if m.get("module_id") == module_id), None)


def compute_plan_hash(*, fixture_id: str, module_id: str, options: dict, marker: str,
                      budgets: dict) -> str:
    blob = json.dumps({"fixture_id": fixture_id, "module_id": module_id, "options": options,
                       "marker": marker, "budgets": budgets}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class ProofError(ValueError):
    pass


def create_plan(db: Session, *, target_id: str, fixture: LabFixture, module_id: str,
                options: dict, operator_id: str, engagement_ref: str,
                issue_id: str | None = None) -> ProofPlan:
    module = _module(module_id)
    if module is None or module.get("admission_state") != "ADMITTED":
        raise ProofError("module is not admitted for execution")
    marker = "nonce-" + secrets.token_hex(8)
    budgets = {"proof_seconds": 120, "total_lifecycle_seconds": 600, "attempts": 1}
    plan_hash = compute_plan_hash(fixture_id=fixture.id, module_id=module_id, options=options,
                                  marker=marker, budgets=budgets)
    plan = ProofPlan(target_id=target_id, fixture_id=fixture.id, issue_id=issue_id,
                     module_id=module_id, options=options, proof_marker=marker, budgets=budgets,
                     plan_hash=plan_hash, engagement_ref=engagement_ref[:256],
                     operator_id=operator_id, state="AWAITING_APPROVAL")
    db.add(plan)
    db.flush()
    AuditService.append(db, actor="system", action="PROOF_PLAN_CREATED", object_type="proof_plan",
                        object_id=plan.id, payload={"module_id": module_id, "plan_hash": plan_hash})
    return plan


def approve_plan(db: Session, plan: ProofPlan, *, admin, attestation: str) -> ProofPlan:
    if plan.state != "AWAITING_APPROVAL":
        raise ProofError(f"plan is not awaiting approval (state {plan.state})")
    if attestation.strip() != PROOF_ATTESTATION:
        raise ProofError("exact proof attestation text is required")
    plan.state = "APPROVED"
    plan.attestation_text = attestation
    plan.approved_by_id = admin.id
    plan.approved_at = _now()
    plan.expires_at = _now() + dt.timedelta(hours=2)
    AuditService.append(db, actor=f"user:{admin.username}", action="PROOF_PLAN_APPROVED",
                        object_type="proof_plan", object_id=plan.id,
                        payload={"plan_hash": plan.plan_hash})
    return plan


def _gate(db: Session, plan: ProofPlan) -> str | None:
    """Return a block reason if any precondition fails, else None."""
    settings = get_settings()
    if not settings.enable_lab_proof:
        return "lab proof execution is disabled (TRASHSCAN_ENABLE_LAB_PROOF=false)"
    if plan.state == "CONSUMED":
        return "plan already consumed (one-shot; request a fresh plan)"
    if plan.state != "APPROVED":
        return f"plan is not approved (state {plan.state})"
    if plan.expires_at and _now() > plan.expires_at:
        return "approval window elapsed"
    module = _module(plan.module_id)
    if module is None or module.get("admission_state") != "ADMITTED":
        return "module is not admitted"
    fixture = db.get(LabFixture, plan.fixture_id)
    env = db.get(LabEnvironment, fixture.lab_environment_id) if fixture else None
    if fixture is None or env is None:
        return "fixture or environment missing"
    ready = lab.readiness(fixture, env)
    if not ready["ready"]:
        return "fixture not proof-ready: " + "; ".join(ready["reasons"])
    # One global active proof at a time.
    active = db.execute(
        select(ProofAttempt).where(ProofAttempt.state.in_(_ACTIVE_STATES))
    ).scalars().first()
    if active is not None:
        return "another proof is already active"
    return None


def _evaluate(native, marker: str) -> tuple[str, bool, bool]:
    """Return (proof_outcome, demonstrated, negative_control_passed). DEMONSTRATED
    only if the exact per-attempt marker is echoed in the raw result AND the
    native verdict is the reviewed condition — never on a bare success."""
    interp = interpret_native_result(native)
    raw = native.raw or {}
    echoed = raw.get("marker") == marker and bool(marker)
    negative_control_passed = bool(raw.get("negative_control_passed"))
    if native.native_code == VULNERABLE and echoed and negative_control_passed:
        return DEMONSTRATED, True, negative_control_passed
    if interp["evidence"] == "INCONCLUSIVE":
        return INCONCLUSIVE, False, negative_control_passed
    return ATTEMPTED_NOT_DEMONSTRATED, False, negative_control_passed


def execute(db: Session, plan: ProofPlan) -> ProofAttempt:
    """One-shot execution. Creates exactly one ProofAttempt; resolves to BLOCKED
    (without running anything) if any gate fails. Never retries."""
    # Gate BEFORE creating the attempt row, so the global "one active proof"
    # check cannot see this very attempt and block itself.
    reason = _gate(db, plan)
    if reason is not None:
        attempt = ProofAttempt(plan_id=plan.id, state="BLOCKED", proof_outcome=BLOCKED,
                               blocked_reason=reason[:512], started_at=_now(), finished_at=_now())
        db.add(attempt)
        db.flush()
        stream.append_status(db, attempt.id, "BLOCKED")
        stream.append_gap(db, attempt.id, reason)
        AuditService.append(db, actor="system:worker", action="PROOF_ATTEMPT_BLOCKED",
                            object_type="proof_attempt", object_id=attempt.id,
                            payload={"reason": reason[:256]})
        return attempt

    attempt = ProofAttempt(plan_id=plan.id, state="PREFLIGHT", started_at=_now())
    db.add(attempt)
    db.flush()

    # Gates passed (only possible with the flag on + a ready fixture). Consume
    # the plan first so it can never start twice, acquire the fixture lock, run
    # once, evaluate, then recover.
    fixture = db.get(LabFixture, plan.fixture_id)
    plan.state = "CONSUMED"
    plan.consumed_at = _now()
    lab.acquire_lock(fixture, f"attempt:{attempt.id}")
    attempt.state = "RUNNING"
    stream.append_status(db, attempt.id, "RUNNING")
    started = _now()
    adapter = _framework()
    try:
        job_id = adapter.start_check(CheckJob(module_id=plan.module_id, target=fixture.target_id,
                                              options=plan.options, idempotency_key=attempt.id))
        native = adapter.job_result(job_id)
        proof_outcome, demonstrated, neg = _evaluate(native, plan.proof_marker)
        summary = f"native={native.native_code}; marker_echoed={demonstrated}"
        db.add(ProofEvidence(attempt_id=attempt.id, marker=plan.proof_marker,
                             demonstrated=demonstrated, native_code=native.native_code,
                             negative_control_passed=neg, redacted_summary=summary))
        attempt.proof_outcome = proof_outcome
        stream.append_output(db, attempt.id, f"check returned: {native.native_code}")
        stream.append_evidence(db, attempt.id, summary)
    except Exception as exc:  # noqa: BLE001 - a module/runner failure is ERROR, not a crash
        attempt.proof_outcome = ERROR
        db.add(ProofEvidence(attempt_id=attempt.id, marker=plan.proof_marker, demonstrated=False,
                             redacted_summary=f"error: {str(exc)[:200]}"))
        stream.append_gap(db, attempt.id, "runner error")

    attempt.measured_runtime_ms = int((_now() - started).total_seconds() * 1000)

    # Recovery is a separate dimension and cannot erase demonstrated evidence.
    attempt.state = "RECOVERING"
    rec = lab.rehearse_restore(db, fixture, lab.FakeLabController(), None)
    attempt.recovery_outcome = (lab.RESTORED_VERIFIED if rec.outcome == lab.RESTORED_VERIFIED
                                else lab.RECOVERY_FAILED)
    lab.release_lock(fixture)
    attempt.state = "COMPLETED"
    attempt.finished_at = _now()
    stream.append_status(db, attempt.id, "COMPLETED")
    AuditService.append(db, actor="system:worker", action="PROOF_ATTEMPT_COMPLETED",
                        object_type="proof_attempt", object_id=attempt.id,
                        payload={"proof_outcome": attempt.proof_outcome,
                                 "recovery_outcome": attempt.recovery_outcome})
    return attempt
