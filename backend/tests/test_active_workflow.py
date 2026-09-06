"""Adversarial tests for the active-scan workflow (PRD §8, §23, §24)."""
from __future__ import annotations

import datetime as dt

import pytest

from app.constants import ACTIVE_SCAN_ATTESTATION
from app.models import (
    EmergencyStop,
    PrivateCidr,
    ScanApproval,
    ScanExecution,
    Service,
    Target,
    User,
)
from app.security import hash_password
from app.services import emergency
from app.services.execution_service import ScanService
from app.services.scope_db import set_resolver
from app.worker import runner


@pytest.fixture
def lab(db):
    admin = User(username="adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    scanner = User(username="scn", role="SCANNER", password_hash=hash_password("x" * 12),
                   is_active=True)
    db.add_all([admin, scanner, PrivateCidr(cidr="10.10.0.0/16")])
    ip_t = Target(kind="IPV4", value="10.10.5.20")
    dom_t = Target(kind="DOMAIN", value="lab.example.com")
    db.add_all([ip_t, dom_t])
    db.flush()
    db.commit()
    return {"admin": admin.id, "scanner": scanner.id, "ip": ip_t.id, "dom": dom_t.id}


def _request_active(db, target_id, user_id, profile="SAFE_ACTIVE") -> tuple[str, str]:
    ex = ScanExecution(target_id=target_id, requested_by_id=user_id, profile=profile,
                       classification="ACTIVE", state="DRAFT",
                       options={"rate_per_second": 5})
    db.add(ex)
    db.flush()
    ScanService.transition(db, ex, "AWAITING_APPROVAL", actor="test")
    approval = ScanApproval(execution_id=ex.id, target_id=target_id, requested_by_id=user_id,
                            profile=profile, attestation_text=ACTIVE_SCAN_ATTESTATION,
                            requested_options={}, scope_at_request={}, state="AWAITING_APPROVAL")
    db.add(approval)
    db.commit()
    return ex.id, approval.id


def _approve(db, approval_id: str, admin_id: str) -> str:
    approval = db.get(ScanApproval, approval_id)
    ex = db.get(ScanExecution, approval.execution_id)
    now = dt.datetime.now(dt.timezone.utc)
    approval.state = "APPROVED"
    approval.expires_at = now + dt.timedelta(hours=2)
    ex.approval_id = approval.id
    ex.approved_at = now
    ex.approval_expires_at = now + dt.timedelta(hours=2)
    ScanService.transition(db, ex, "APPROVED", actor="test")
    ScanService.transition(db, ex, "QUEUED", actor="test")
    ex.queued_at = now
    db.commit()
    return ex.id


def test_approved_active_scan_runs_and_records_services(db, lab):
    ex_id, ap_id = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap_id, lab["admin"])
    assert runner.execute(ex_id) == "COMPLETED"
    db.expire_all()
    ex = db.get(ScanExecution, ex_id)
    assert ex.state == "COMPLETED"
    assert ex.tool_versions.get("nmap")
    assert db.query(Service).filter(Service.target_id == lab["ip"]).count() > 0


def test_expired_approval_cannot_start(db, lab):
    ex_id, ap_id = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap_id, lab["admin"])
    ex = db.get(ScanExecution, ex_id)
    ex.approval_expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert runner.execute(ex_id) == "EXPIRED"
    db.expire_all()
    assert db.get(ScanExecution, ex_id).state == "EXPIRED"
    assert db.query(Service).count() == 0  # no tool launched


def test_completed_scan_is_not_replayable(db, lab):
    ex_id, ap_id = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap_id, lab["admin"])
    assert runner.execute(ex_id) == "COMPLETED"
    svc_count = db.query(Service).count()
    # a duplicate task delivery must be a no-op
    assert runner.execute(ex_id) == "COMPLETED"
    assert db.query(Service).count() == svc_count


def test_scope_recheck_blocks_launch_when_domain_leaves_scope(db, lab):
    ex_id, ap_id = _request_active(db, lab["dom"], lab["scanner"], profile="STANDARD_ACTIVE")
    _approve(db, ap_id, lab["admin"])
    # DNS now answers with a public address -> re-check must fail before any tool
    set_resolver(lambda _domain: ["203.0.113.55"])
    try:
        assert runner.execute(ex_id) == "FAILED"
    finally:
        set_resolver(None)
    db.expire_all()
    ex = db.get(ScanExecution, ex_id)
    assert ex.state == "FAILED"
    assert "scope re-check" in (ex.cancel_reason or ex.error or "")
    assert db.query(Service).count() == 0


def test_runtime_cap_times_out_running_scan(db, lab):
    ex_id, ap_id = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap_id, lab["admin"])
    ex = db.get(ScanExecution, ex_id)
    ScanService.transition(db, ex, "RUNNING", actor="test")
    ex.runtime_deadline_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert runner.execute(ex_id) == "TIMED_OUT"
    db.expire_all()
    assert db.get(ScanExecution, ex_id).state == "TIMED_OUT"
    assert db.get(ScanExecution, ex_id).partial is True


def test_emergency_stop_cancels_queued_and_blocks_new(db, lab):
    ex_id, ap_id = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap_id, lab["admin"])  # now QUEUED
    emergency.request_stop(db, actor="user:adm", requester_id=lab["admin"], scope="ALL",
                           execution_ids=[], note="drill")
    db.commit()
    db.expire_all()
    assert db.get(ScanExecution, ex_id).state == "CANCELLED"

    # a fresh execution cannot start while the stop is active
    ex2, ap2 = _request_active(db, lab["ip"], lab["scanner"])
    _approve(db, ap2, lab["admin"])
    assert runner.execute(ex2) == "CANCELLED"

    stop = db.query(EmergencyStop).one()
    emergency.reconcile(db)
    db.commit()
    db.refresh(stop)
    assert stop.state == "CONFIRMED"
