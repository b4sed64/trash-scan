"""Findings and scan comparison (PRD §9.3, §11.4, §15)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    CandidateAssociation,
    Finding,
    FindingSighting,
    Issue,
    Occurrence,
    ScanComparison,
    ScanExecution,
    User,
)
from ..services import AuditService, AuthorizationService
from ..services.authorization_service import PermissionDenied
from ..services.findings import severity_rank
from ..services.issues import backfill_all
from ..services import vulnintel
from .deps import get_current_user, require_admin, require_csrf

router = APIRouter(tags=["findings"])


def _access_or_404(db: Session, user: User, target_id: str):
    try:
        return AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc


def _finding_dto(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "source_tool": f.source_tool,
        "template_hash": f.template_hash,
        "severity": f.severity,
        "name": f.name,
        "description": f.description,
        "asset_value": f.asset_value,
        "port": f.port,
        "protocol": f.protocol,
        "matcher_name": f.matcher_name,
        "evidence_summary": f.evidence_summary,
        "status": f.status,
        "first_seen_at": f.first_seen_at,
        "last_seen_at": f.last_seen_at,
        "first_execution_id": f.first_execution_id,
        "last_execution_id": f.last_execution_id,
        "requires_validation": True,
    }


@router.get("/api/findings")
def list_all_findings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
) -> list[dict]:
    """Findings across every target the requester may see, ranked by severity."""
    visible = {t.id: t.value for t in AuthorizationService.visible_targets(db, user)}
    rows = db.execute(
        select(Finding).where(Finding.target_id.in_(list(visible) or ["__none__"]))
    ).scalars().all()
    if severity:
        rows = [f for f in rows if f.severity == severity.upper()]
    if status_filter:
        rows = [f for f in rows if f.status == status_filter.upper()]
    rows.sort(key=lambda f: (-severity_rank(f.severity), f.status != "OBSERVED", f.rule_id))
    out = []
    for f in rows:
        dto = _finding_dto(f)
        dto["target_id"] = f.target_id
        dto["target_value"] = visible.get(f.target_id, "")
        out.append(dto)
    return out


@router.get("/api/targets/{target_id}/findings")
def list_findings(
    target_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    tool: str | None = Query(default=None),
) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Finding).where(Finding.target_id == target_id)
    ).scalars().all()
    if severity:
        rows = [f for f in rows if f.severity == severity.upper()]
    if status_filter:
        rows = [f for f in rows if f.status == status_filter.upper()]
    if tool:
        rows = [f for f in rows if f.source_tool == tool]
    rows.sort(key=lambda f: (-severity_rank(f.severity), f.rule_id))
    return [_finding_dto(f) for f in rows]


@router.get("/api/findings/{finding_id}")
def get_finding(finding_id: str, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> dict:
    f = db.get(Finding, finding_id)
    if f is None or not AuthorizationService.can_view_target(db, user, f.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    sightings = db.execute(
        select(FindingSighting).where(FindingSighting.finding_id == finding_id)
        .order_by(FindingSighting.seen_at.asc())
    ).scalars().all()
    dto = _finding_dto(f)
    dto["fingerprint"] = f.fingerprint
    dto["evidence"] = f.evidence
    dto["sightings"] = [
        {"execution_id": s.execution_id, "severity": s.severity,
         "evidence_key": s.evidence_key, "seen_at": s.seen_at}
        for s in sightings
    ]
    return dto


# --- canonical issues (PRD v2 Phase 9) -----------------------------------

@router.get("/api/issues")
def list_issues(user: User = Depends(get_current_user), db: Session = Depends(get_db),
                severity: str | None = Query(default=None),
                status_filter: str | None = Query(default=None, alias="status")) -> list[dict]:
    """Canonical issues across every target the requester may see. Each rolls up
    one or more findings (including equivalent detectors from different tools)."""
    visible = {t.id: t.value for t in AuthorizationService.visible_targets(db, user)}
    rows = db.execute(
        select(Issue).where(Issue.target_id.in_(list(visible) or ["__none__"]))
    ).scalars().all()
    if severity:
        rows = [i for i in rows if i.severity == severity.upper()]
    if status_filter:
        rows = [i for i in rows if i.status == status_filter.upper()]
    rows.sort(key=lambda i: (-severity_rank(i.severity), i.status != "OBSERVED", i.issue_type))
    out = []
    for i in rows:
        occ_count = db.execute(
            select(Occurrence).where(Occurrence.issue_id == i.id)
        ).scalars().all()
        out.append({
            "id": i.id, "target_id": i.target_id, "target_value": visible.get(i.target_id, ""),
            "issue_type": i.issue_type, "category": i.category, "title": i.title,
            "severity": i.severity, "status": i.status,
            "first_seen_at": i.first_seen_at, "last_seen_at": i.last_seen_at,
            "occurrence_count": len(occ_count),
            "requires_validation": True,
        })
    return out


@router.get("/api/issues/{issue_id}")
def get_issue(issue_id: str, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)) -> dict:
    issue = db.get(Issue, issue_id)
    if issue is None or not AuthorizationService.can_view_target(db, user, issue.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
    occurrences = db.execute(
        select(Occurrence).where(Occurrence.issue_id == issue_id)
        .order_by(Occurrence.seen_at.asc())
    ).scalars().all()
    # The legacy finding ids this canonical issue aliases (dedup, order stable).
    finding_ids: list[str] = []
    for o in occurrences:
        if o.finding_id not in finding_ids:
            finding_ids.append(o.finding_id)
    return {
        "id": issue.id, "target_id": issue.target_id, "issue_type": issue.issue_type,
        "category": issue.category, "title": issue.title, "severity": issue.severity,
        "status": issue.status, "first_seen_at": issue.first_seen_at,
        "last_seen_at": issue.last_seen_at, "requires_validation": True,
        "legacy_finding_ids": finding_ids,
        "occurrences": [
            {"execution_id": o.execution_id, "finding_id": o.finding_id,
             "asset_value": o.asset_value, "port": o.port, "severity": o.severity,
             "seen_at": o.seen_at}
            for o in occurrences
        ],
    }


@router.post("/api/admin/issues/backfill", dependencies=[Depends(require_csrf)])
def backfill_issues(admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Rebuild the canonical issue projection from all existing findings.
    Idempotent and lossless — the underlying findings are never modified."""
    totals = backfill_all(db)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="ISSUES_BACKFILLED",
        object_type="issue", object_id="*", payload=totals,
    )
    db.commit()
    return totals


# --- offline CVE intelligence (PRD v2 Phase 11) --------------------------

@router.get("/api/vulnintel/status")
def vulnintel_status(user: User = Depends(get_current_user)) -> dict:
    """Local snapshot provider, effective date and freshness (§9.2). Missing or
    stale data is reported as such — never silently treated as zero risk."""
    return vulnintel.snapshot_status()


def _candidate_dto(c: CandidateAssociation) -> dict:
    return {
        "id": c.id, "cve_id": c.cve_id, "product": c.product,
        "version_evidence": c.version_evidence, "matched_cpe": c.matched_cpe,
        "version_range": c.version_range, "applicability": c.applicability,
        "confidence": c.confidence, "cvss_version": c.cvss_version, "cvss_score": c.cvss_score,
        "kev": c.kev, "epss_score": c.epss_score, "epss_percentile": c.epss_percentile,
        "advisory_source": c.advisory_source, "match_rationale": c.match_rationale,
        "priority_lane": c.priority_lane, "priority_reasons": c.priority_reasons,
        "applicability_rule_version": c.applicability_rule_version,
        "snapshot_version": c.snapshot_version,
        # Candidates are not confirmed findings — they require manual validation.
        "requires_validation": True,
    }


@router.get("/api/targets/{target_id}/candidates")
def list_candidates(target_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> list[dict]:
    """Candidate CVE associations for a target. These are separate from the
    actionable finding/issue counts: a candidate means "might be affected,
    pending reviewed applicability", not a confirmed vulnerability."""
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(CandidateAssociation).where(CandidateAssociation.target_id == target_id)
    ).scalars().all()
    lane_order = {"VALIDATE_URGENT": 0, "VALIDATE": 1, "P1": 2, "P2": 3, "P3": 4, "P4": 5}
    rows.sort(key=lambda c: (lane_order.get(c.priority_lane, 9), -(c.cvss_score or 0), c.cve_id))
    return [_candidate_dto(c) for c in rows]


@router.post("/api/admin/vulnintel/refresh", dependencies=[Depends(require_csrf)])
def refresh_vulnintel(admin: User = Depends(require_admin),
                      db: Session = Depends(get_db)) -> dict:
    """Re-derive candidate associations for all completed scans from the current
    local snapshot (§9.2: a new snapshot may re-prioritize without a rescan).
    Audited as ENRICHMENT_UPDATED; does not change any scan's observation time."""
    result = vulnintel.backfill_candidates(db)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="ENRICHMENT_UPDATED",
        object_type="candidate_association", object_id="*",
        payload={"candidates": result["candidates"], "executions": result["executions"],
                 "snapshot": result["snapshot"]},
    )
    db.commit()
    return result


def _comparison_dto(c: ScanComparison) -> dict:
    return {
        "execution_id": c.execution_id,
        "baseline_execution_id": c.baseline_execution_id,
        "eligible": c.eligible,
        "summary": c.summary,
        "limitations": c.limitations,
        "details": c.details,
        "created_at": c.created_at,
    }


@router.get("/api/scans/{execution_id}/comparison")
def scan_comparison(execution_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    ex = db.get(ScanExecution, execution_id)
    if ex is None or not AuthorizationService.can_view_target(db, user, ex.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    c = db.execute(
        select(ScanComparison).where(ScanComparison.execution_id == execution_id)
    ).scalar_one_or_none()
    if c is None:
        return {"execution_id": execution_id, "eligible": False,
                "summary": {"note": "no comparison recorded for this execution"},
                "limitations": [], "details": [], "baseline_execution_id": None}
    return _comparison_dto(c)


@router.get("/api/targets/{target_id}/comparison")
def latest_comparison(target_id: str, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> dict:
    _access_or_404(db, user, target_id)
    row = db.execute(
        select(ScanComparison)
        .join(ScanExecution, ScanExecution.id == ScanComparison.execution_id)
        .where(ScanExecution.target_id == target_id)
        .order_by(ScanComparison.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no comparison yet")
    return _comparison_dto(row)
