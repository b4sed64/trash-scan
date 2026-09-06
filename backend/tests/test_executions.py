"""Execution state machine, passive runner, and idempotency (PRD §10, NFR-08)."""
from __future__ import annotations

import datetime as dt

import pytest

from app.models import Asset, Observation, PrivateCidr, ScanExecution, Target, User
from app.security import hash_password
from app.services.execution_service import IllegalTransition, ScanService
from app.worker import runner


@pytest.fixture
def lab(db):
    admin = User(username="a", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    db.add(admin)
    db.add(PrivateCidr(cidr="10.10.0.0/16"))
    target = Target(kind="DOMAIN", value="lab.example.com")
    db.add(target)
    db.flush()
    db.commit()
    return {"admin": admin.id, "target": target.id}


def _queue(db, target_id, user_id) -> str:
    ex = ScanExecution(target_id=target_id, requested_by_id=user_id, profile="PASSIVE",
                       classification="PASSIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc))
    db.add(ex)
    db.commit()
    return ex.id


def test_passive_runner_completes_and_normalizes(db, lab):
    ex_id = _queue(db, lab["target"], lab["admin"])
    assert runner.execute(ex_id) == "COMPLETED"

    db.expire_all()
    ex = db.get(ScanExecution, ex_id)
    assert ex.state == "COMPLETED"
    assert ex.tool_versions  # recorded for reproducibility (SCAN-10)
    assert ex.parser_version == "3"

    assets = db.query(Asset).filter(Asset.target_id == lab["target"]).all()
    assert assets, "expected discovered assets"
    assert all(a.approved is False for a in assets), "discoveries must be unapproved"
    # the 10.x fake IPs are inside the configured private range
    assert any(a.kind == "IP" and a.in_scope for a in assets)
    assert db.query(Observation).filter(Observation.target_id == lab["target"]).count() > 0


def test_runner_is_idempotent_on_terminal(db, lab):
    ex_id = _queue(db, lab["target"], lab["admin"])
    assert runner.execute(ex_id) == "COMPLETED"
    obs_before = db.query(Observation).count()
    # a duplicate queue message must not double results or re-transition
    assert runner.execute(ex_id) == "COMPLETED"
    assert db.query(Observation).count() == obs_before


def test_state_machine_rejects_illegal_transition(db, lab):
    ex_id = _queue(db, lab["target"], lab["admin"])
    ex = db.get(ScanExecution, ex_id)
    with pytest.raises(IllegalTransition):
        ScanService.transition(db, ex, "COMPLETED", actor="test")


def test_cancel_before_start_is_terminal(db, lab):
    ex_id = _queue(db, lab["target"], lab["admin"])
    ex = db.get(ScanExecution, ex_id)
    ex.cancel_requested = True
    db.commit()
    assert runner.execute(ex_id) == "CANCELLED"
    db.expire_all()
    assert db.get(ScanExecution, ex_id).state == "CANCELLED"
