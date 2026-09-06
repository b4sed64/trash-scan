"""ComparisonService — classify findings against a compatible baseline (PRD §9.3, §15.3).

Classifications: NEW, STILL_OBSERVED, CHANGED, NOT_OBSERVED.

Rules:
  * only compare with a previous *completed* execution whose target and relevant
    profile are compatible;
  * an incomplete or failed stage in the current execution cannot establish
    NOT_OBSERVED for findings owned by that stage — those are reported as a
    limitation instead;
  * NOT_OBSERVED never means "resolved".
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, FindingSighting, ScanComparison, ScanExecution
from .audit_service import AuditService
from .findings import severity_rank

NEW = "NEW"
STILL_OBSERVED = "STILL_OBSERVED"
CHANGED = "CHANGED"
NOT_OBSERVED = "NOT_OBSERVED"

# Which stage owns which source tool's findings.
_STAGE_FOR_TOOL = {"nuclei": "nuclei"}


def find_baseline(db: Session, execution: ScanExecution) -> ScanExecution | None:
    rows = db.execute(
        select(ScanExecution)
        .where(
            ScanExecution.target_id == execution.target_id,
            ScanExecution.id != execution.id,
            ScanExecution.state == "COMPLETED",
            ScanExecution.classification == execution.classification,
            ScanExecution.created_at < execution.created_at,
        )
        .order_by(ScanExecution.finished_at.desc())
        .limit(1)
    ).scalars().all()
    return rows[0] if rows else None


def _stage_ok(execution: ScanExecution, stage_name: str) -> bool:
    for meta in execution.stages or []:
        if meta.get("stage") == stage_name:
            return bool(meta.get("ok")) and not meta.get("incomplete")
    return False


def _sightings(db: Session, execution_id: str) -> dict[str, FindingSighting]:
    return {
        s.finding_id: s
        for s in db.execute(
            select(FindingSighting).where(FindingSighting.execution_id == execution_id)
        ).scalars()
    }


def compare(db: Session, execution: ScanExecution, baseline: ScanExecution | None) -> dict:
    limitations: list[str] = []
    if baseline is None:
        return {
            "eligible": False,
            "baseline_execution_id": None,
            "summary": {"note": "no compatible baseline execution exists yet"},
            "limitations": ["First comparable scan for this target."],
            "details": [],
        }

    if execution.profile != baseline.profile:
        limitations.append(
            f"Profile differs (this: {execution.profile}, baseline: {baseline.profile}); "
            "port and service coverage may not be comparable."
        )

    cur = _sightings(db, execution.id)
    base = _sightings(db, baseline.id)
    finding_ids = set(cur) | set(base)
    findings = {
        f.id: f
        for f in db.execute(select(Finding).where(Finding.id.in_(finding_ids or ["__none__"])))
        .scalars()
    }

    # For each source stage, can this execution establish NOT_OBSERVED?
    can_absent: dict[str, bool] = {}
    for tool, stage_name in _STAGE_FOR_TOOL.items():
        ok = _stage_ok(execution, stage_name)
        can_absent[tool] = ok
        if not ok:
            limitations.append(
                f"The {stage_name} stage did not complete in this scan; findings from it that "
                "were seen before are not classified as NOT_OBSERVED."
            )

    details = []
    counts = {NEW: 0, STILL_OBSERVED: 0, CHANGED: 0, NOT_OBSERVED: 0}
    by_severity: dict[str, int] = {}

    for fid in finding_ids:
        f = findings.get(fid)
        if f is None:
            continue
        in_cur, in_base = fid in cur, fid in base
        if in_cur and not in_base:
            verdict = NEW
        elif in_cur and in_base:
            sc, sb = cur[fid], base[fid]
            verdict = CHANGED if (sc.evidence_key != sb.evidence_key or sc.severity != sb.severity) \
                else STILL_OBSERVED
        else:  # in baseline, not current
            if not can_absent.get(f.source_tool, False):
                continue  # cannot classify — covered by the limitation above
            verdict = NOT_OBSERVED

        counts[verdict] += 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        details.append({
            "finding_id": fid,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity,
            "asset": f.asset_value,
            "port": f.port,
            "classification": verdict,
            "evidence_summary": f.evidence_summary,
        })

    details.sort(key=lambda d: (-severity_rank(d["severity"]), d["classification"]))
    return {
        "eligible": True,
        "baseline_execution_id": baseline.id,
        "summary": {"counts": counts, "by_severity": by_severity,
                    "total_findings": len(details)},
        "limitations": limitations,
        "details": details,
    }


def build_and_store(db: Session, execution: ScanExecution) -> ScanComparison:
    baseline = find_baseline(db, execution)
    result = compare(db, execution, baseline)

    existing = db.execute(
        select(ScanComparison).where(ScanComparison.execution_id == execution.id)
    ).scalar_one_or_none()
    row = existing or ScanComparison(execution_id=execution.id)
    row.baseline_execution_id = result["baseline_execution_id"]
    row.eligible = result["eligible"]
    row.summary = result["summary"]
    row.limitations = result["limitations"]
    row.details = result["details"]
    if existing is None:
        db.add(row)

    # Reflect NOT_OBSERVED onto the finding rows (never "resolved").
    for d in result["details"]:
        if d["classification"] == NOT_OBSERVED:
            f = db.get(Finding, d["finding_id"])
            if f is not None:
                f.status = "NOT_OBSERVED"

    AuditService.append(
        db, actor="system:worker", action="SCAN_COMPARISON_BUILT",
        object_type="scan_execution", object_id=execution.id,
        payload={"baseline": result["baseline_execution_id"], "eligible": result["eligible"],
                 "summary": result["summary"], "limitations": result["limitations"]},
    )
    return row
