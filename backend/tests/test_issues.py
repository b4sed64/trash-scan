"""Canonical issues, equivalent-detector mapping, lossless backfill (Phase 9)."""
from __future__ import annotations

import datetime as dt

import pytest

from app.models import (
    Finding,
    FindingSighting,
    Issue,
    Occurrence,
    PrivateCidr,
    ScanExecution,
    Target,
    User,
)
from app.security import hash_password
from app.services.issues import backfill_all, canonical_issue_type, derive_issues
from app.worker import runner


# --- equivalence mapping ---------------------------------------------------


def test_shared_tls_rules_are_tool_independent():
    # httpx -tls-grab and nmap ssl-cert emit the same rule id -> same class
    assert canonical_issue_type("httpx", "tls-cert-expired") == "tls:tls-cert-expired"
    assert canonical_issue_type("nmap", "tls-cert-expired") == "tls:tls-cert-expired"


def test_unshared_rules_stay_tool_qualified():
    assert (canonical_issue_type("nuclei", "trashscan-git-config-exposure")
            == "nuclei:trashscan-git-config-exposure")
    # different tools, different rules never collapse
    assert (canonical_issue_type("httpx", "server-header")
            != canonical_issue_type("nuclei", "server-header-x"))


# --- derivation fixtures ---------------------------------------------------


@pytest.fixture
def lab(db):
    u = User(username="iss", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.30")
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def _exec(db, target_id) -> ScanExecution:
    ex = ScanExecution(target_id=target_id, profile="SAFE_ACTIVE", classification="ACTIVE",
                       state="COMPLETED", created_at=dt.datetime.now(dt.timezone.utc),
                       finished_at=dt.datetime.now(dt.timezone.utc))
    db.add(ex)
    db.flush()
    return ex


def _finding(db, target_id, *, tool, rule, asset, sev="HIGH", port=443) -> Finding:
    f = Finding(target_id=target_id, fingerprint=f"{tool}:{rule}:{asset}:{port}",
                source_tool=tool, rule_id=rule, severity=sev, name=rule,
                asset_value=asset, port=port, status="OBSERVED")
    db.add(f)
    db.flush()
    return f


def _sight(db, finding, execution, sev="HIGH"):
    db.add(FindingSighting(finding_id=finding.id, execution_id=execution.id, severity=sev,
                           seen_at=dt.datetime.now(dt.timezone.utc)))
    db.flush()


# --- behavior --------------------------------------------------------------


def test_equivalent_detectors_from_two_tools_collapse_to_one_issue(db, lab):
    ex = _exec(db, lab["target"])
    f_httpx = _finding(db, lab["target"], tool="httpx", rule="tls-cert-expired", asset="10.10.5.30")
    f_nmap = _finding(db, lab["target"], tool="nmap", rule="tls-cert-expired", asset="10.10.5.30")
    _sight(db, f_httpx, ex)
    _sight(db, f_nmap, ex)
    db.commit()

    derive_issues(db, ex)
    db.commit()

    issues = db.query(Issue).filter(Issue.target_id == lab["target"]).all()
    assert len(issues) == 1
    assert issues[0].issue_type == "tls:tls-cert-expired"
    # both tools' findings are preserved as distinct occurrences (no evidence lost)
    occ = db.query(Occurrence).filter(Occurrence.issue_id == issues[0].id).all()
    assert {o.finding_id for o in occ} == {f_httpx.id, f_nmap.id}


def test_unrelated_detectors_are_not_merged(db, lab):
    ex = _exec(db, lab["target"])
    f1 = _finding(db, lab["target"], tool="nuclei", rule="trashscan-git-config-exposure",
                  asset="10.10.5.30", sev="MEDIUM")
    f2 = _finding(db, lab["target"], tool="nuclei", rule="trashscan-env-file-exposure",
                  asset="10.10.5.30", sev="HIGH")
    _sight(db, f1, ex)
    _sight(db, f2, ex)
    db.commit()
    derive_issues(db, ex)
    db.commit()
    assert db.query(Issue).filter(Issue.target_id == lab["target"]).count() == 2


def test_distinct_hosts_sharing_a_type_are_distinct_occurrences(db, lab):
    ex = _exec(db, lab["target"])
    # same issue type, two different hostnames resolving behind one target
    f_a = _finding(db, lab["target"], tool="nuclei", rule="trashscan-directory-listing",
                   asset="a.lab.internal")
    f_b = _finding(db, lab["target"], tool="nuclei", rule="trashscan-directory-listing",
                   asset="b.lab.internal")
    _sight(db, f_a, ex)
    _sight(db, f_b, ex)
    db.commit()
    derive_issues(db, ex)
    db.commit()
    issues = db.query(Issue).filter(Issue.target_id == lab["target"]).all()
    assert len(issues) == 1  # one canonical issue type
    occ = db.query(Occurrence).filter(Occurrence.issue_id == issues[0].id).all()
    assert {o.asset_value for o in occ} == {"a.lab.internal", "b.lab.internal"}


def test_backfill_is_lossless_and_idempotent(db, lab):
    ex = ScanExecution(target_id=lab["target"], requested_by_id=lab["user"], profile="SAFE_ACTIVE",
                       classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"  # forward-derives issues already
    db.expire_all()

    sightings = db.query(FindingSighting).count()
    assert sightings > 0
    # every sighting projected to exactly one occurrence (nothing lost)
    assert db.query(Occurrence).count() == sightings

    # re-running the backfill must not duplicate or drop anything
    backfill_all(db)
    db.commit()
    assert db.query(Occurrence).count() == sightings
    backfill_all(db)
    db.commit()
    assert db.query(Occurrence).count() == sightings
