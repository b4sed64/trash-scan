"""Finding fingerprints, normalization, and baseline comparison (PRD §15, §27.1)."""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import DiscoveredFinding, StageOutput
from app.models import Finding, FindingSighting, PrivateCidr, ScanComparison, ScanExecution, Target, User
from app.security import hash_password
from app.services import comparison as cmp
from app.services.execution_service import ScanService
from app.services.findings import fingerprint, record_findings
from app.worker import runner


def test_fingerprint_ignores_volatile_evidence():
    base = dict(target_id="t1", asset_value="10.10.5.20", source_tool="nuclei",
                rule_id="trashscan-x", protocol="tcp", port=80)
    a = fingerprint(**base, evidence_key="trashscan-x|word|nginx")
    b = fingerprint(**base, evidence_key="trashscan-x|word|nginx")
    c = fingerprint(**base, evidence_key="trashscan-x|word|apache")
    assert a == b and a != c


def test_fingerprint_distinguishes_asset_and_rule():
    common = dict(source_tool="nuclei", protocol="tcp", port=80, evidence_key="k")
    f1 = fingerprint(target_id="t", asset_value="a", rule_id="r1", **common)
    f2 = fingerprint(target_id="t", asset_value="a", rule_id="r2", **common)
    f3 = fingerprint(target_id="t", asset_value="b", rule_id="r1", **common)
    assert len({f1, f2, f3}) == 3


@pytest.fixture
def lab(db):
    u = User(username="a", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.20")
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def _run_active(db, target_id, user_id) -> str:
    ex = ScanExecution(target_id=target_id, requested_by_id=user_id, profile="SAFE_ACTIVE",
                       classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    return ex.id


def test_first_active_scan_findings_are_new(db, lab):
    ex_id = _run_active(db, lab["target"], lab["user"])
    db.expire_all()
    findings = db.query(Finding).filter(Finding.target_id == lab["target"]).all()
    assert findings, "fake nuclei should emit findings"
    assert all(f.status == "OBSERVED" for f in findings)
    comp = db.query(ScanComparison).filter(ScanComparison.execution_id == ex_id).one()
    assert comp.eligible is False  # no baseline yet
    assert db.query(FindingSighting).count() == len(findings)


def test_repeated_scan_is_still_observed(db, lab):
    _run_active(db, lab["target"], lab["user"])
    ex2 = _run_active(db, lab["target"], lab["user"])
    db.expire_all()
    comp = db.query(ScanComparison).filter(ScanComparison.execution_id == ex2).one()
    assert comp.eligible is True
    counts = comp.summary["counts"]
    assert counts["STILL_OBSERVED"] > 0
    assert counts["NEW"] == 0
    assert counts["NOT_OBSERVED"] == 0


def test_finding_that_disappears_is_not_observed_not_resolved(db, lab):
    from app.adapters import fake

    _run_active(db, lab["target"], lab["user"])
    # second scan: the fake nuclei adapter drops one rule
    orig = fake.FakeNucleiAdapter.run

    def patched(self, inp):
        inp.options["_fake_findings_drop"] = "trashscan-nginx-default-page"
        return orig(self, inp)

    fake.FakeNucleiAdapter.run = patched
    try:
        ex2 = _run_active(db, lab["target"], lab["user"])
    finally:
        fake.FakeNucleiAdapter.run = orig

    db.expire_all()
    comp = db.query(ScanComparison).filter(ScanComparison.execution_id == ex2).one()
    verdicts = {d["rule_id"]: d["classification"] for d in comp.details}
    assert verdicts.get("trashscan-nginx-default-page") == "NOT_OBSERVED"
    dropped = db.query(Finding).filter(Finding.rule_id == "trashscan-nginx-default-page").one()
    assert dropped.status == "NOT_OBSERVED"  # never "RESOLVED"


def test_incomplete_stage_cannot_establish_not_observed(db, lab):
    ex1 = _run_active(db, lab["target"], lab["user"])
    # craft a second execution whose nuclei stage is marked incomplete, with no
    # nuclei sightings, and compare against ex1
    ex2 = ScanExecution(target_id=lab["target"], profile="SAFE_ACTIVE", classification="ACTIVE",
                        state="COMPLETED", created_at=dt.datetime.now(dt.timezone.utc),
                        finished_at=dt.datetime.now(dt.timezone.utc),
                        stages=[{"stage": "nuclei", "ok": False, "incomplete": True}])
    db.add(ex2)
    db.commit()
    result = cmp.compare(db, ex2, db.get(ScanExecution, ex1))
    assert all(d["classification"] != "NOT_OBSERVED" for d in result["details"])
    assert any("did not complete" in lim for lim in result["limitations"])


def test_severity_change_is_classified_changed(db, lab):
    ex1 = _run_active(db, lab["target"], lab["user"])
    # bump the severity of one finding's sighting, then compare a fresh execution
    f = db.query(Finding).first()
    ex2_id = _run_active(db, lab["target"], lab["user"])
    db.expire_all()
    s = db.query(FindingSighting).filter(
        FindingSighting.finding_id == f.id, FindingSighting.execution_id == ex1
    ).one()
    s.severity = "CRITICAL"
    db.commit()
    result = cmp.compare(db, db.get(ScanExecution, ex2_id), db.get(ScanExecution, ex1))
    assert any(d["classification"] == "CHANGED" for d in result["details"])


def test_template_manifest_tamper_is_detected(tmp_path):
    from app.adapters.nuclei import verify_template_set

    tdir = tmp_path / "nuclei"
    tdir.mkdir()
    (tmp_path / "nuclei-manifest.json").write_text('{"templates": {"a.yaml": "deadbeef"}}')
    (tdir / "a.yaml").write_text("id: a\ninfo:\n  name: a\n  severity: info\n")
    ok, _, reason = verify_template_set(tdir)
    assert ok is False and "hash" in reason


def test_stage_output_carries_findings():
    out = StageOutput(stage="nuclei", ok=True, tool="nuclei", tool_version="x")
    out.findings.append(DiscoveredFinding(
        rule_id="r", template_hash="h", severity="LOW", name="n", description="d",
        asset_value="10.10.5.20", matched_at="http://x/", evidence_key="k",
    ))
    assert out.findings[0].rule_id == "r"
