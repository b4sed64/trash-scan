"""Lab isolation / snapshot / health / recovery gating (PRD v2 Phase 15).

Fake controller only — nothing touches a hypervisor or a target. The central
guarantee is that a fixture is NOT proof-ready until isolation is verified, a
restore rehearsal succeeds, and baseline health is HEALTHY; and that a failed
restore records RECOVERY_FAILED and keeps the fixture not-ready.
"""
from __future__ import annotations

import pytest

from app.models import LabEnvironment, LabFixture, PrivateCidr, Target, User
from app.security import hash_password
from app.services import lab


@pytest.fixture
def labenv(db):
    admin = User(username="labadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    db.add_all([admin, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.9.9")
    env = LabEnvironment(name="lab-a", provider="fake")
    db.add_all([t, env])
    db.flush()
    f = LabFixture(lab_environment_id=env.id, target_id=t.id, name="web-fixture", build_id="b1")
    db.add(f)
    db.flush()
    db.commit()
    return {"admin": admin.id, "env": env, "fixture": f}


# --- readiness gating ------------------------------------------------------


def test_fresh_fixture_is_not_ready(db, labenv):
    r = lab.readiness(labenv["fixture"], labenv["env"])
    assert r["ready"] is False
    # every missing precondition is named
    joined = " ".join(r["reasons"])
    assert "isolation not verified" in joined
    assert "restore rehearsal" in joined
    assert "baseline health" in joined


def test_fixture_ready_only_after_isolation_restore_and_health(db, labenv):
    env, fixture = labenv["env"], labenv["fixture"]
    controller = lab.FakeLabController(isolation_ok=True, health=lab.HEALTHY, restore_ok=True)
    lab.verify_isolation(db, env, controller)
    lab.rehearse_restore(db, fixture, controller, labenv["admin"])
    db.commit()
    r = lab.readiness(fixture, env)
    assert r["ready"] is True, r["reasons"]


def test_failed_restore_blocks_and_records_recovery_failed(db, labenv):
    env, fixture = labenv["env"], labenv["fixture"]
    controller = lab.FakeLabController(isolation_ok=True, restore_ok=False)
    lab.verify_isolation(db, env, controller)
    rec = lab.rehearse_restore(db, fixture, controller, labenv["admin"])
    db.commit()
    assert rec.outcome == lab.RECOVERY_FAILED
    assert fixture.baseline_health == lab.RECOVERY_FAILED
    assert lab.readiness(fixture, env)["ready"] is False


def test_isolation_failure_keeps_not_verified(db, labenv):
    env = labenv["env"]
    ok = lab.verify_isolation(db, env, lab.FakeLabController(isolation_ok=False))
    assert ok is False
    assert env.isolation_verified is False


# --- exclusive lock --------------------------------------------------------


def test_exclusive_lock(db, labenv):
    fixture = labenv["fixture"]
    lab.acquire_lock(fixture, "attempt-1")
    with pytest.raises(lab.LockError):
        lab.acquire_lock(fixture, "attempt-2")
    # same holder is idempotent; a locked fixture is not ready
    lab.acquire_lock(fixture, "attempt-1")
    assert lab.readiness(fixture, labenv["env"])["ready"] is False
    lab.release_lock(fixture)
    assert fixture.locked_by is None
