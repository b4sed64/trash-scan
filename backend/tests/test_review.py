"""Issue review, remediation, risk exceptions, closure/reopen, JSON export (Phase 12)."""
from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import (
    CandidateAssociation,
    Finding,
    FindingSighting,
    Issue,
    Notification,
    PrivateCidr,
    ScanExecution,
    Target,
    User,
)
from app.security import hash_password
from app.services import review
from app.services.issues import derive_issues

ADMIN_PW = "admin-password-123"


@pytest.fixture
def lab(db):
    admin = User(username="rvadm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    db.add_all([admin, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.50")
    db.add(t)
    db.flush()
    db.commit()
    return {"admin": admin.id, "target": t.id}


def _issue(db, target_id, **kw) -> Issue:
    i = Issue(target_id=target_id, issue_type="nuclei:trashscan-git-config-exposure",
              category="nuclei", title="Exposed .git", severity="MEDIUM", status="OBSERVED")
    for k, v in kw.items():
        setattr(i, k, v)
    db.add(i)
    db.flush()
    return i


# --- validation / assignment ----------------------------------------------


def test_validation_transition(db, lab):
    i = _issue(db, lab["target"])
    review.set_validation(db, i, "FALSE_POSITIVE", "user:x")
    assert i.validation_state == "FALSE_POSITIVE"
    with pytest.raises(review.ReviewError):
        review.set_validation(db, i, "BOGUS", "user:x")


def test_assign_moves_open_to_in_progress(db, lab):
    i = _issue(db, lab["target"])
    review.assign(db, i, owner="team-a", due_date=None, desired_state="patched",
                  plan="upgrade", actor="user:x")
    assert i.owner == "team-a"
    assert i.remediation_state == "IN_PROGRESS"


# --- risk exceptions -------------------------------------------------------


def test_accept_risk_requires_reason(db, lab):
    i = _issue(db, lab["target"])
    admin = db.get(User, lab["admin"])
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    with pytest.raises(review.ReviewError):
        review.accept_risk(db, i, reason="   ", scope="", controls="", expires_at=future, admin=admin)
    exc = review.accept_risk(db, i, reason="accepted for lab", scope="host", controls="fw",
                             expires_at=future, admin=admin)
    assert i.remediation_state == "RISK_ACCEPTED"
    assert exc.active is True


def test_expire_due_exceptions(db, lab):
    i = _issue(db, lab["target"])
    admin = db.get(User, lab["admin"])
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    exc = review.accept_risk(db, i, reason="r", scope="s", controls="", expires_at=past, admin=admin)
    db.flush()
    assert review.expire_due_exceptions(db) == 1
    assert exc.active is False


# --- closure: negative scan alone is never sufficient ----------------------


def test_close_refused_without_negative_or_manual_evidence(db, lab):
    i = _issue(db, lab["target"], status="OBSERVED")
    admin = db.get(User, lab["admin"])
    with pytest.raises(review.ReviewError):
        review.verify_closure(db, i, admin=admin, reason="fixed", evidence_ref="",
                              manually_verified=False)


def test_close_with_manual_evidence(db, lab):
    i = _issue(db, lab["target"], status="OBSERVED")
    admin = db.get(User, lab["admin"])
    review.verify_closure(db, i, admin=admin, reason="patched out of band",
                          evidence_ref="ticket-123 + screenshot", manually_verified=True)
    assert i.remediation_state == "RESOLVED_VERIFIED"
    assert i.verification_method == "MANUAL"


def test_close_via_qualifying_negative(db, lab):
    i = _issue(db, lab["target"], status="NOT_OBSERVED")
    admin = db.get(User, lab["admin"])
    review.verify_closure(db, i, admin=admin, reason="retest clean", evidence_ref="",
                          manually_verified=False)
    assert i.remediation_state == "RESOLVED_VERIFIED"
    assert i.verification_method == "RETEST_NEGATIVE"


# --- reopen after verified closure -----------------------------------------


def test_reopen_after_verified_closure(db, lab):
    i = _issue(db, lab["target"], status="OBSERVED")
    admin = db.get(User, lab["admin"])
    review.verify_closure(db, i, admin=admin, reason="fixed", evidence_ref="ev",
                          manually_verified=True)
    db.commit()
    assert i.remediation_state == "RESOLVED_VERIFIED"

    ex = ScanExecution(target_id=lab["target"], profile="SAFE_ACTIVE", classification="ACTIVE",
                       state="COMPLETED", created_at=dt.datetime.now(dt.timezone.utc),
                       finished_at=dt.datetime.now(dt.timezone.utc))
    db.add(ex)
    db.flush()
    f = Finding(target_id=lab["target"], fingerprint="fp-reopen", source_tool="nuclei",
                rule_id="trashscan-git-config-exposure", severity="MEDIUM", name="Exposed .git",
                asset_value="10.10.5.50", status="OBSERVED")
    db.add(f)
    db.flush()
    db.add(FindingSighting(finding_id=f.id, execution_id=ex.id, severity="MEDIUM",
                           seen_at=dt.datetime.now(dt.timezone.utc)))
    db.flush()
    derive_issues(db, ex)
    db.commit()
    db.refresh(i)
    assert i.reopened is True
    assert i.remediation_state == "OPEN"
    assert db.query(Notification).filter(Notification.kind == "ISSUE_REOPENED").count() >= 1


# --- API: admin gating + redacted JSON export ------------------------------


_ADMIN_LOGIN = {"username": "rvadm", "password": "xxxxxxxxxxxx"}  # the lab fixture's admin


def test_scanner_cannot_close_an_issue(client, db, lab):
    client.post("/api/auth/login", json=_ADMIN_LOGIN)
    csrf = client.cookies.get("trashscan_csrf")
    sc = client.post("/api/admin/accounts",
                     json={"username": "scan1", "password": "scanner-password-1", "role": "SCANNER"},
                     headers={"X-CSRF-Token": csrf}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": csrf})
    with TestClient(create_app()) as s:
        s.post("/api/auth/login", json={"username": "scan1", "password": "scanner-password-1"})
        r = s.post("/api/issues/any-id/close", json={"reason": "x"},
                   headers={"X-CSRF-Token": s.cookies.get("trashscan_csrf")})
        assert r.status_code == 403


def test_json_export_preserves_excluded_candidates_and_coverage(client, db, lab):
    # one active issue, one false-positive (excluded), one candidate
    _issue(db, lab["target"], issue_type="nuclei:a", title="active", status="OBSERVED")
    _issue(db, lab["target"], issue_type="nuclei:b", title="fp", validation_state="FALSE_POSITIVE")
    db.add(CandidateAssociation(target_id=lab["target"], cve_id="CVE-X", product="nginx",
                                version_evidence="1.0", applicability="CANDIDATE",
                                priority_lane="VALIDATE"))
    db.commit()

    client.post("/api/auth/login", json=_ADMIN_LOGIN)
    r = client.get(f"/api/targets/{lab['target']}/report.json")
    assert r.status_code == 200
    body = r.json()
    assert body["counts"]["active_total"] == 1
    assert body["counts"]["excluded_total"] == 1
    assert body["counts"]["candidate_total"] == 1
    assert any(c["cve_id"] == "CVE-X" for c in body["candidates"])
