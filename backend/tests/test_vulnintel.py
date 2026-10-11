"""Offline CVE intelligence and deterministic priority (PRD v2 Phase 11).

Everything here is offline: matching is a pure function over (products,
snapshot), and the end-to-end path injects a snapshot via ``set_snapshot`` so no
file or network is touched. Candidates are kept separate from findings/issues.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from app.models import CandidateAssociation, Finding, PrivateCidr, ScanExecution, Target, User
from app.security import hash_password
from app.services import vulnintel
from app.services.vulnintel import (
    CANDIDATE,
    SUPPORTED,
    UNKNOWN,
    match_candidates,
    priority_lane,
    set_snapshot,
    snapshot_status,
)
from app.worker import runner

_SNAP = {
    "provider": "test-offline",
    "schema_version": "1",
    "effective_at": "2026-01-01T00:00:00Z",
    "records": [
        {"cve": "CVE-T-1", "product": "nginx", "version_start_incl": "0",
         "version_end_excl": "1.21.0", "cvss_version": "3.1", "cvss_score": 7.5,
         "kev": False, "epss_score": 0.04, "epss_percentile": 0.6, "advisory": "x"},
        {"cve": "CVE-T-2", "product": "openssh", "version_start_incl": "0",
         "version_end_excl": "9.0", "cvss_version": "3.1", "cvss_score": 9.8,
         "kev": True, "epss_score": 0.42, "epss_percentile": 0.95, "advisory": "x"},
    ],
}


@pytest.fixture(autouse=True)
def _reset_snapshot():
    yield
    set_snapshot(None)


# --- matching (pure, offline) ---------------------------------------------


def test_version_in_range_is_candidate():
    res = match_candidates([("nginx", "1.0")], _SNAP)
    assert len(res) == 1
    assert res[0]["cve_id"] == "CVE-T-1"
    assert res[0]["applicability"] == CANDIDATE


def test_version_out_of_range_is_not_stored():
    # 1.25.0 is outside [0, 1.21.0) -> NOT_APPLICABLE, dropped as noise
    assert match_candidates([("nginx", "1.25.0")], _SNAP) == []


def test_product_only_match_is_unknown():
    res = match_candidates([("openssh", "")], _SNAP)
    assert len(res) == 1
    assert res[0]["applicability"] == UNKNOWN


def test_unrelated_product_matches_nothing():
    assert match_candidates([("lighttpd", "1.4")], _SNAP) == []


# --- deterministic priority lanes (§11.1) ---------------------------------


def test_candidate_in_kev_is_validate_urgent():
    lane, reasons = priority_lane(CANDIDATE, kev=True, cvss_score=9.8, epss_score=0.4)
    assert lane == "VALIDATE_URGENT"
    assert "candidate-cve-in-kev" in reasons


def test_plain_candidate_is_validate():
    lane, _ = priority_lane(CANDIDATE, kev=False, cvss_score=7.5, epss_score=0.04)
    assert lane == "VALIDATE"


def test_unknown_applicability_routes_to_validation_not_low():
    lane, reasons = priority_lane(UNKNOWN, kev=False, cvss_score=None, epss_score=None)
    assert lane == "VALIDATE"
    assert "unknown-applicability-needs-review" in reasons


def test_supported_critical_is_p1_and_supported_high_is_p2():
    assert priority_lane(SUPPORTED, kev=False, cvss_score=9.8, epss_score=0.0)[0] == "P1"
    assert priority_lane(SUPPORTED, kev=False, cvss_score=7.5, epss_score=0.0)[0] == "P2"
    assert priority_lane(SUPPORTED, kev=False, cvss_score=5.0, epss_score=0.0)[0] == "P3"
    assert priority_lane(SUPPORTED, kev=False, cvss_score=0.0, epss_score=0.0)[0] == "P4"


# --- snapshot status -------------------------------------------------------


def test_snapshot_status_fresh_and_stale():
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    set_snapshot({**_SNAP, "effective_at": now})
    assert snapshot_status()["status"] == "FRESH"
    set_snapshot({**_SNAP, "effective_at": "2000-01-01T00:00:00Z"})
    assert snapshot_status()["status"] == "STALE"


def test_snapshot_status_missing(monkeypatch):
    set_snapshot(None)
    monkeypatch.setattr(vulnintel, "get_settings",
                        lambda: SimpleNamespace(vulnintel_snapshot_path="/nope.json",
                                                vulnintel_stale_hours=72))
    status = snapshot_status()
    assert status["status"] == "MISSING"
    assert status["stale"] is True


# --- end to end: candidates derived, kept separate from findings ----------


@pytest.fixture
def lab(db):
    u = User(username="vi", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.40")
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def test_scan_derives_candidates_without_inflating_findings(db, lab):
    set_snapshot(_SNAP)
    ex = ScanExecution(target_id=lab["target"], requested_by_id=lab["user"], profile="SAFE_ACTIVE",
                       classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    db.expire_all()

    cands = db.query(CandidateAssociation).filter(
        CandidateAssociation.target_id == lab["target"]).all()
    cves = {c.cve_id for c in cands}
    assert "CVE-T-2" in cves  # openssh 1.0 in range
    openssh = next(c for c in cands if c.cve_id == "CVE-T-2")
    assert openssh.kev is True
    assert openssh.priority_lane == "VALIDATE_URGENT"

    # candidates are a SEPARATE table; they are not Finding rows
    finding_rule_ids = {f.rule_id for f in db.query(Finding).all()}
    assert not (cves & finding_rule_ids)
