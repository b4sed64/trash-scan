"""Lab isolation, snapshots, health and recovery — fake controller (PRD v2 §21.6, Phase 15).

Models the safety infrastructure that *gates* proof execution; it runs nothing
against a target. The real provider integration follows the operator's actual
hypervisor/topology and is deliberately not invented here — the controller is a
fake, and a fixture only becomes proof-ready once isolation is proven, a restore
rehearsal is recorded and baseline health is HEALTHY. Until then readiness is
False, which is exactly what keeps real execution BLOCKED in a dev environment.
"""
from __future__ import annotations

import datetime as dt
from typing import Protocol

from sqlalchemy.orm import Session

from ..models import LabEnvironment, LabFixture, RecoveryRecord

# Health (§21.6) and recovery (§21.7) vocabularies.
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
UNKNOWN = "UNKNOWN"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
RECOVERY_FAILED = "RECOVERY_FAILED"

NOT_NEEDED = "NOT_NEEDED"
PENDING = "PENDING"
VERIFIED_CLEAN = "VERIFIED_CLEAN"
RESTORED_VERIFIED = "RESTORED_VERIFIED"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class LabController(Protocol):
    """The operations a lab provider must offer. A real provider implements this
    against the operator's hypervisor; the fake below is used for development."""

    def verify_isolation(self, env: LabEnvironment) -> tuple[bool, str]: ...
    def check_health(self, fixture: LabFixture) -> str: ...
    def snapshot(self, fixture: LabFixture) -> str: ...
    def restore(self, fixture: LabFixture) -> bool: ...


class FakeLabController:
    """Deterministic fake. It does not touch any hypervisor or network; it only
    returns recorded/simulated values so the gating, locking and recovery logic
    can be exercised offline."""

    def __init__(self, *, isolation_ok: bool = True, health: str = HEALTHY,
                 restore_ok: bool = True):
        self._isolation_ok = isolation_ok
        self._health = health
        self._restore_ok = restore_ok

    def verify_isolation(self, env: LabEnvironment) -> tuple[bool, str]:
        if self._isolation_ok:
            return True, "fake: target-only egress; control-plane/internet/other-targets blocked"
        return False, "fake: isolation proof failed"

    def check_health(self, fixture: LabFixture) -> str:
        return self._health

    def snapshot(self, fixture: LabFixture) -> str:
        return f"fake-snapshot-digest:{fixture.id}"

    def restore(self, fixture: LabFixture) -> bool:
        return self._restore_ok


def readiness(fixture: LabFixture, env: LabEnvironment) -> dict:
    """Is the fixture ready to host an active proof? Ready only when every safety
    precondition holds. Any gap keeps execution BLOCKED (§21.6)."""
    reasons: list[str] = []
    if not env.isolation_verified:
        reasons.append("lab environment isolation not verified")
    if not fixture.snapshot_digest:
        reasons.append("no bound snapshot")
    if not fixture.restore_rehearsed:
        reasons.append("no recorded successful restore rehearsal")
    if fixture.baseline_health != HEALTHY:
        reasons.append(f"baseline health is {fixture.baseline_health}, not HEALTHY")
    if fixture.locked_by:
        reasons.append(f"fixture is locked by {fixture.locked_by}")
    return {"ready": not reasons, "reasons": reasons}


class LockError(RuntimeError):
    pass


def acquire_lock(fixture: LabFixture, holder: str) -> None:
    if fixture.locked_by and fixture.locked_by != holder:
        raise LockError(f"fixture already locked by {fixture.locked_by}")
    fixture.locked_by = holder
    fixture.locked_at = _now()


def release_lock(fixture: LabFixture) -> None:
    fixture.locked_by = None
    fixture.locked_at = None


def rehearse_restore(db: Session, fixture: LabFixture, controller: LabController,
                     actor_id: str | None) -> RecoveryRecord:
    """Record a restore rehearsal (§21.6: snapshot presence alone is insufficient).
    On success marks the fixture rehearsed and HEALTHY; on failure records
    RECOVERY_FAILED and leaves the fixture not-ready."""
    if not fixture.snapshot_digest:
        fixture.snapshot_digest = controller.snapshot(fixture)
    ok = controller.restore(fixture)
    if ok:
        fixture.restore_rehearsed = True
        fixture.restore_rehearsal_at = _now()
        fixture.baseline_health = controller.check_health(fixture)
        outcome, detail = RESTORED_VERIFIED, "restore rehearsal succeeded; baseline health checked"
    else:
        fixture.restore_rehearsed = False
        fixture.baseline_health = RECOVERY_FAILED
        outcome, detail = RECOVERY_FAILED, "restore rehearsal failed"
    rec = RecoveryRecord(fixture_id=fixture.id, outcome=outcome, detail=detail,
                         created_by_id=actor_id)
    db.add(rec)
    return rec


def verify_isolation(db: Session, env: LabEnvironment, controller: LabController) -> bool:
    ok, proof = controller.verify_isolation(env)
    env.isolation_verified = ok
    env.isolation_proof_ref = proof[:256]
    return ok
