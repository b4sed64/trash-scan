"""Lab environment / fixture / recovery API (PRD v2 §21.6/§21.8, Phase 15).

Read endpoints for the Lab Proof area and admin-only registration/verification.
Everything here manages the *gating* metadata; nothing executes against a
target. A fixture is never proof-ready until isolation is verified, a restore
rehearsal is recorded, and baseline health is HEALTHY.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    LabEnvironment,
    LabFixture,
    ProofAttempt,
    ProofPlan,
    RecoveryRecord,
    Target,
    User,
)
from ..services import AuditService, AuthorizationService
from ..services import lab, proof
from ..services.authorization_service import PermissionDenied
from .deps import get_current_user, require_admin, require_csrf

router = APIRouter(tags=["lab"])


def _target_access_or_404(db: Session, user: User, target_id: str) -> None:
    try:
        AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc

# Development controller: a fake that touches no hypervisor/network. A real
# provider is wired per the operator's topology and gated by the real-lab proof.
_controller = lab.FakeLabController()


class EnvBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider: str = Field(default="fake", max_length=32)
    egress_policy: str = Field(default="", max_length=512)


class FixtureBody(BaseModel):
    lab_environment_id: str
    target_id: str
    name: str = Field(default="", max_length=128)
    build_id: str = Field(default="", max_length=128)


def _env_dto(e: LabEnvironment) -> dict:
    return {"id": e.id, "name": e.name, "provider": e.provider,
            "egress_policy": e.egress_policy, "isolation_verified": e.isolation_verified,
            "isolation_proof_ref": e.isolation_proof_ref}


def _fixture_dto(db: Session, f: LabFixture) -> dict:
    env = db.get(LabEnvironment, f.lab_environment_id)
    return {"id": f.id, "lab_environment_id": f.lab_environment_id, "target_id": f.target_id,
            "name": f.name, "build_id": f.build_id, "snapshot_digest": f.snapshot_digest,
            "baseline_health": f.baseline_health, "restore_rehearsed": f.restore_rehearsed,
            "locked_by": f.locked_by,
            "readiness": lab.readiness(f, env) if env else {"ready": False,
                                                            "reasons": ["environment missing"]}}


@router.get("/api/lab/environments")
def list_environments(user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> list[dict]:
    return [_env_dto(e) for e in db.execute(select(LabEnvironment)).scalars()]


@router.post("/api/admin/lab/environments", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_environment(body: EnvBody, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)) -> dict:
    if db.execute(select(LabEnvironment).where(LabEnvironment.name == body.name)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "a lab environment with that name exists")
    env = LabEnvironment(name=body.name, provider=body.provider, egress_policy=body.egress_policy,
                         created_by_id=admin.id)
    db.add(env)
    db.flush()
    AuditService.append(db, actor=f"user:{admin.username}", action="LAB_ENVIRONMENT_REGISTERED",
                        object_type="lab_environment", object_id=env.id, payload={"name": env.name})
    db.commit()
    return _env_dto(env)


@router.post("/api/admin/lab/environments/{env_id}/verify-isolation",
             dependencies=[Depends(require_csrf)])
def verify_isolation(env_id: str, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)) -> dict:
    """Record an isolation verification. With the fake controller this is a
    simulated result for development — a REAL deployment must demonstrate
    target-only traffic / blocked control-plane+internet+other-targets on the
    actual topology before this means anything."""
    env = db.get(LabEnvironment, env_id)
    if env is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "environment not found")
    ok = lab.verify_isolation(db, env, _controller)
    AuditService.append(db, actor=f"user:{admin.username}", action="LAB_ISOLATION_VERIFIED",
                        object_type="lab_environment", object_id=env.id,
                        payload={"verified": ok, "provider": env.provider, "simulated": True})
    db.commit()
    return _env_dto(env)


@router.get("/api/lab/fixtures")
def list_fixtures(user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)) -> list[dict]:
    return [_fixture_dto(db, f) for f in db.execute(select(LabFixture)).scalars()]


@router.post("/api/admin/lab/fixtures", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_fixture(body: FixtureBody, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)) -> dict:
    if db.get(LabEnvironment, body.lab_environment_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lab environment not found")
    if db.get(Target, body.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if db.execute(select(LabFixture).where(LabFixture.target_id == body.target_id)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "target already bound to a fixture")
    f = LabFixture(lab_environment_id=body.lab_environment_id, target_id=body.target_id,
                   name=body.name, build_id=body.build_id)
    db.add(f)
    db.flush()
    AuditService.append(db, actor=f"user:{admin.username}", action="LAB_FIXTURE_REGISTERED",
                        object_type="lab_fixture", object_id=f.id,
                        payload={"target_id": body.target_id, "build_id": body.build_id})
    db.commit()
    return _fixture_dto(db, f)


@router.post("/api/admin/lab/fixtures/{fixture_id}/rehearse-restore",
             dependencies=[Depends(require_csrf)])
def rehearse_restore(fixture_id: str, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)) -> dict:
    f = db.get(LabFixture, fixture_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "fixture not found")
    rec = lab.rehearse_restore(db, f, _controller, admin.id)
    AuditService.append(db, actor=f"user:{admin.username}", action="LAB_RESTORE_REHEARSED",
                        object_type="lab_fixture", object_id=f.id,
                        payload={"outcome": rec.outcome, "simulated": True})
    db.commit()
    return _fixture_dto(db, f)


@router.get("/api/lab/fixtures/{fixture_id}/readiness")
def fixture_readiness(fixture_id: str, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> dict:
    f = db.get(LabFixture, fixture_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "fixture not found")
    env = db.get(LabEnvironment, f.lab_environment_id)
    result = lab.readiness(f, env)
    recovery = db.execute(
        select(RecoveryRecord).where(RecoveryRecord.fixture_id == f.id)
        .order_by(RecoveryRecord.created_at.desc())
    ).scalars().first()
    result["last_recovery"] = {"outcome": recovery.outcome, "detail": recovery.detail} if recovery else None
    return result


# --- one-shot proof execution (PRD v2 §21.5, Phase 16) -------------------

class ProofPlanBody(BaseModel):
    target_id: str
    fixture_id: str
    module_id: str
    options: dict = Field(default_factory=dict)
    engagement_ref: str = Field(default="", max_length=256)
    issue_id: str | None = None


class ApproveBody(BaseModel):
    attestation: str


def _plan_dto(p: ProofPlan) -> dict:
    return {"id": p.id, "target_id": p.target_id, "fixture_id": p.fixture_id,
            "module_id": p.module_id, "state": p.state, "plan_hash": p.plan_hash,
            "proof_marker": p.proof_marker, "budgets": p.budgets,
            "engagement_ref": p.engagement_ref, "expires_at": p.expires_at,
            "approved_at": p.approved_at}


def _attempt_dto(db: Session, a: ProofAttempt) -> dict:
    from ..models import ProofEvidence
    ev = db.execute(select(ProofEvidence).where(ProofEvidence.attempt_id == a.id)).scalars().all()
    return {"id": a.id, "plan_id": a.plan_id, "state": a.state,
            "proof_outcome": a.proof_outcome, "recovery_outcome": a.recovery_outcome,
            "blocked_reason": a.blocked_reason, "measured_runtime_ms": a.measured_runtime_ms,
            "evidence": [{"marker": e.marker, "demonstrated": e.demonstrated,
                          "native_code": e.native_code,
                          "negative_control_passed": e.negative_control_passed,
                          "redacted_summary": e.redacted_summary} for e in ev]}


@router.post("/api/proof/plans", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_proof_plan(body: ProofPlanBody, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> dict:
    _target_access_or_404(db, user, body.target_id)
    fixture = db.get(LabFixture, body.fixture_id)
    if fixture is None or fixture.target_id != body.target_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "fixture not found for this target")
    try:
        plan = proof.create_plan(db, target_id=body.target_id, fixture=fixture,
                                 module_id=body.module_id, options=body.options,
                                 operator_id=user.id, engagement_ref=body.engagement_ref,
                                 issue_id=body.issue_id)
    except proof.ProofError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    db.commit()
    return _plan_dto(plan)


@router.post("/api/proof/plans/{plan_id}/approve", dependencies=[Depends(require_csrf)])
def approve_proof_plan(plan_id: str, body: ApproveBody, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)) -> dict:
    plan = db.get(ProofPlan, plan_id)
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "plan not found")
    try:
        proof.approve_plan(db, plan, admin=admin, attestation=body.attestation)
    except proof.ProofError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    db.commit()
    return _plan_dto(plan)


@router.post("/api/proof/plans/{plan_id}/execute", dependencies=[Depends(require_csrf)])
def execute_proof_plan(plan_id: str, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)) -> dict:
    plan = db.get(ProofPlan, plan_id)
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "plan not found")
    _target_access_or_404(db, user, plan.target_id)
    attempt = proof.execute(db, plan)
    db.commit()
    return _attempt_dto(db, attempt)


@router.get("/api/proof/attempts/{attempt_id}")
def get_proof_attempt(attempt_id: str, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> dict:
    a = db.get(ProofAttempt, attempt_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "attempt not found")
    plan = db.get(ProofPlan, a.plan_id)
    if plan is not None:
        _target_access_or_404(db, user, plan.target_id)
    return _attempt_dto(db, a)
