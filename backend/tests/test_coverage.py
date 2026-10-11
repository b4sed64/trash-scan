"""Coverage ledger and evidence foundation (PRD v2 Phase 8).

The point of the coverage ledger is to tell "assessed and clean" apart from
"never actually checked", so an incomplete or skipped stage can never silently
clear a previously-seen finding. ``coverage_outcome`` is unit-tested directly,
then the end-to-end pipeline and the comparison guard are exercised.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import StageOutput
from app.models import (
    CoverageEntry,
    PrivateCidr,
    ScanExecution,
    Target,
    User,
)
from app.security import hash_password
from app.services import comparison as cmp
from app.services.coverage import (
    ASSESSED,
    COMPLETED_WITH_GAPS,
    INCONCLUSIVE,
    NOT_ASSESSED,
    coverage_outcome,
)
from app.worker import runner


def _out(**kw) -> StageOutput:
    base = dict(stage="nuclei", ok=True, tool="nuclei", tool_version="x")
    base.update(kw)
    return StageOutput(**base)


# --- coverage_outcome: the conservative mapping ---------------------------


def test_clean_run_is_assessed():
    assert coverage_outcome(_out())[0] == ASSESSED


def test_incomplete_run_is_completed_with_gaps():
    # a timeout / truncation / budget exhaustion sets incomplete
    assert coverage_outcome(_out(incomplete=True))[0] == COMPLETED_WITH_GAPS


def test_missing_tool_is_not_assessed():
    o = _out(ok=False, incomplete=True,
             stderr_excerpt="nuclei binary not found in worker image")
    assert coverage_outcome(o)[0] == NOT_ASSESSED


def test_exit_zero_skipped_check_is_not_assessed():
    # ok=True but nothing was in scope — an exit-zero skip is NOT a clean negative
    outcome, reason = coverage_outcome(_out(note="no approved hosts to probe"))
    assert outcome == NOT_ASSESSED
    assert "no approved hosts" in reason


def test_unconfirmed_run_is_inconclusive():
    assert coverage_outcome(_out(ok=False))[0] == INCONCLUSIVE


# --- end-to-end + comparison guard ----------------------------------------


@pytest.fixture
def lab(db):
    u = User(username="cov", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
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


def test_scan_records_immutable_coverage_entries(db, lab):
    ex_id = _run_active(db, lab["target"], lab["user"])
    db.expire_all()
    entries = db.query(CoverageEntry).filter(CoverageEntry.execution_id == ex_id).all()
    assert entries, "a completed scan must record coverage"
    # one entry per stage, and the nuclei family assessed cleanly in the fake pipeline
    by_stage = {e.stage: e.outcome for e in entries}
    assert by_stage.get("nuclei") == ASSESSED
    # every entry carries a defined outcome from the allowed set
    allowed = {ASSESSED, COMPLETED_WITH_GAPS, NOT_ASSESSED, INCONCLUSIVE}
    assert all(e.outcome in allowed for e in entries)


def test_exit_zero_skipped_stage_cannot_clear_a_prior_finding(db, lab):
    """The core Phase 8 guarantee: a stage that exits clean but assessed nothing
    (coverage NOT_ASSESSED) must not mark a previously-seen finding NOT_OBSERVED.
    The legacy ok/incomplete logic would have wrongly cleared it."""
    ex1 = _run_active(db, lab["target"], lab["user"])
    ex2 = ScanExecution(
        target_id=lab["target"], profile="SAFE_ACTIVE", classification="ACTIVE",
        state="COMPLETED", created_at=dt.datetime.now(dt.timezone.utc),
        finished_at=dt.datetime.now(dt.timezone.utc),
        # ok=True + not incomplete, but coverage says the unit was not assessed
        stages=[{"stage": "nuclei", "ok": True, "incomplete": False,
                 "coverage": NOT_ASSESSED, "coverage_reason": "no approved hosts to probe"}],
    )
    db.add(ex2)
    db.commit()
    result = cmp.compare(db, ex2, db.get(ScanExecution, ex1))
    assert all(d["classification"] != "NOT_OBSERVED" for d in result["details"])
    assert any("did not complete" in lim for lim in result["limitations"])
