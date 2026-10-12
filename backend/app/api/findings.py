"""Findings and scan comparison (PRD §9.3, §11.4, §15)."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import (
    CandidateAssociation,
    CoverageEntry,
    ExploitabilityAssessment,
    Finding,
    FindingSighting,
    Issue,
    Occurrence,
    RiskException,
    ScanComparison,
    ScanExecution,
    User,
)
from ..services import AuditService, AuthorizationService
from ..services.authorization_service import PermissionDenied
from ..services.findings import severity_rank
from ..services.issues import backfill_all
from ..services import exploitability, review, vulnintel
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


# --- issue review / remediation (PRD v2 Phase 12) ------------------------

class ValidateBody(BaseModel):
    state: str
    reason: str = ""


class AssignBody(BaseModel):
    owner: str = ""
    due_date: dt.datetime | None = None
    desired_state: str = ""
    plan: str = ""


class MitigateBody(BaseModel):
    note: str = ""


class AcceptRiskBody(BaseModel):
    reason: str
    scope: str = ""
    compensating_controls: str = ""
    expires_at: dt.datetime


class CloseBody(BaseModel):
    reason: str
    evidence_ref: str = ""
    manually_verified: bool = False


def _issue_or_404(db: Session, user: User, issue_id: str) -> Issue:
    issue = db.get(Issue, issue_id)
    if issue is None or not AuthorizationService.can_view_target(db, user, issue.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
    return issue


def _issue_review_dto(db: Session, issue: Issue) -> dict:
    exceptions = db.execute(
        select(RiskException).where(RiskException.issue_id == issue.id)
        .order_by(RiskException.created_at.desc())
    ).scalars().all()
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "id": issue.id, "issue_type": issue.issue_type, "severity": issue.severity,
        "status": issue.status, "validation_state": issue.validation_state,
        "remediation_state": issue.remediation_state, "owner": issue.owner,
        "due_date": issue.due_date, "desired_state": issue.desired_state,
        "remediation_plan": issue.remediation_plan, "reopened": issue.reopened,
        "closed_at": issue.closed_at, "closure_reason": issue.closure_reason,
        "verification_method": issue.verification_method,
        "manually_verified": issue.manually_verified,
        "risk_exceptions": [
            {"id": e.id, "reason": e.reason, "scope": e.scope,
             "compensating_controls": e.compensating_controls, "expires_at": e.expires_at,
             "active": e.active, "overdue": bool(e.active and e.expires_at and e.expires_at < now)}
            for e in exceptions
        ],
    }


@router.post("/api/issues/{issue_id}/validate", dependencies=[Depends(require_csrf)])
def validate_issue(issue_id: str, body: ValidateBody, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> dict:
    issue = _issue_or_404(db, user, issue_id)
    try:
        review.set_validation(db, issue, body.state.upper(), f"user:{user.username}", body.reason)
    except review.ReviewError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    db.commit()
    return _issue_review_dto(db, issue)


@router.post("/api/issues/{issue_id}/assign", dependencies=[Depends(require_csrf)])
def assign_issue(issue_id: str, body: AssignBody, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)) -> dict:
    issue = _issue_or_404(db, user, issue_id)
    review.assign(db, issue, owner=body.owner, due_date=body.due_date,
                  desired_state=body.desired_state, plan=body.plan, actor=f"user:{user.username}")
    db.commit()
    return _issue_review_dto(db, issue)


@router.post("/api/issues/{issue_id}/mitigate", dependencies=[Depends(require_csrf)])
def mitigate_issue(issue_id: str, body: MitigateBody, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> dict:
    issue = _issue_or_404(db, user, issue_id)
    review.set_mitigated(db, issue, f"user:{user.username}", body.note)
    db.commit()
    return _issue_review_dto(db, issue)


@router.post("/api/issues/{issue_id}/accept-risk", dependencies=[Depends(require_csrf)])
def accept_risk_issue(issue_id: str, body: AcceptRiskBody, admin: User = Depends(require_admin),
                      db: Session = Depends(get_db)) -> dict:
    issue = _issue_or_404(db, admin, issue_id)
    try:
        review.accept_risk(db, issue, reason=body.reason, scope=body.scope,
                           controls=body.compensating_controls, expires_at=body.expires_at,
                           admin=admin)
    except review.ReviewError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    db.commit()
    return _issue_review_dto(db, issue)


@router.post("/api/issues/{issue_id}/close", dependencies=[Depends(require_csrf)])
def close_issue(issue_id: str, body: CloseBody, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)) -> dict:
    issue = _issue_or_404(db, admin, issue_id)
    try:
        review.verify_closure(db, issue, admin=admin, reason=body.reason,
                              evidence_ref=body.evidence_ref,
                              manually_verified=body.manually_verified)
    except review.ReviewError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    return _issue_review_dto(db, issue)


@router.get("/api/targets/{target_id}/report.json")
def target_report_json(target_id: str, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)) -> dict:
    """Redacted JSON export (PRD v2 §13.2). Preserves candidates, excluded
    dispositions (false-positive / accepted-risk / verified) with visible totals,
    and the latest coverage so "what was assessed" is explicit. Evidence is the
    already-bounded summary, never raw payloads."""
    tgt = _access_or_404(db, user, target_id)
    issues = db.execute(select(Issue).where(Issue.target_id == target_id)).scalars().all()
    candidates = db.execute(
        select(CandidateAssociation).where(CandidateAssociation.target_id == target_id)
    ).scalars().all()
    latest = db.execute(
        select(ScanExecution).where(ScanExecution.target_id == target_id,
                                    ScanExecution.state == "COMPLETED")
        .order_by(ScanExecution.finished_at.desc()).limit(1)
    ).scalar_one_or_none()
    coverage = []
    if latest is not None:
        coverage = [
            {"stage": c.stage, "check_family": c.check_family, "outcome": c.outcome,
             "reason": c.reason}
            for c in db.execute(
                select(CoverageEntry).where(CoverageEntry.execution_id == latest.id)
            ).scalars()
        ]

    def _excluded(i: Issue) -> bool:
        return (i.remediation_state in review.EXCLUDED_REMEDIATION
                or i.validation_state in review.EXCLUDED_VALIDATION)

    issue_rows = [{
        "id": i.id, "issue_type": i.issue_type, "severity": i.severity, "status": i.status,
        "validation_state": i.validation_state, "remediation_state": i.remediation_state,
        "owner": i.owner, "reopened": i.reopened, "excluded": _excluded(i),
    } for i in issues]
    active = [r for r in issue_rows if not r["excluded"]]
    excluded = [r for r in issue_rows if r["excluded"]]

    # Session evidence / recovery summary (PRD v2 Phase 21): distinguishes
    # demonstrated effect, session state, transcript gaps and recovery incidents.
    from ..models import LabSession, ProofPlan
    from ..services import session_evidence
    plan_ids = [p.id for p in db.execute(
        select(ProofPlan).where(ProofPlan.target_id == target_id)).scalars()]
    sessions = []
    if plan_ids:
        from ..models import ProofAttempt
        attempt_ids = [a.id for a in db.execute(
            select(ProofAttempt).where(ProofAttempt.plan_id.in_(plan_ids))).scalars()]
        if attempt_ids:
            for s in db.execute(
                    select(LabSession).where(LabSession.attempt_id.in_(attempt_ids))).scalars():
                sessions.append(session_evidence.session_report(db, s))

    AuditService.append(db, actor=f"user:{user.username}", action="REPORT_EXPORTED",
                        object_type="target", object_id=target_id, payload={"format": "json"})
    db.commit()
    return {
        "target": {"id": target_id, "value": tgt.value, "kind": tgt.kind},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "counts": {"active_total": len(active), "excluded_total": len(excluded),
                   "candidate_total": len(candidates)},
        "issues": issue_rows,
        "candidates": [
            {"cve_id": c.cve_id, "product": c.product, "version_evidence": c.version_evidence,
             "applicability": c.applicability, "priority_lane": c.priority_lane,
             "kev": c.kev, "cvss_score": c.cvss_score}
            for c in candidates
        ],
        "coverage": coverage,
        "sessions": sessions,
        "notes": [
            "Candidate CVEs require manual validation and are not counted as confirmed findings.",
            "Excluded issues (false-positive / accepted-risk / verified) are retained here with totals.",
            "A clean result only means 'not observed' where coverage shows the family was ASSESSED.",
            "Session evidence distinguishes demonstrated effect, session state, transcript gaps and recovery incidents.",
        ],
    }


# --- exploitability assessment (PRD v2 Phase 13, offline only) -----------

class DryRunBody(BaseModel):
    params: dict = {}


def _assessment_enabled() -> None:
    if not get_settings().enable_exploitability_assessment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "exploitability assessment is disabled")


@router.get("/api/proof/modules")
def list_proof_modules(user: User = Depends(get_current_user)) -> dict:
    """The reviewed proof-module registry. RESEARCH_ONLY modules are visible
    references; ADMITTED modules may be assessed offline. This never executes
    anything and exposes no framework console."""
    _assessment_enabled()
    mods = [
        {"module_id": m.get("module_id"), "admission_state": m.get("admission_state"),
         "claim": m.get("claim", ""), "check_classification": m.get("check_classification", ""),
         "issue_types": m.get("issue_types") or [], "compatible": m.get("compatible") or {},
         "expected_effect": m.get("expected_effect", "")}
        for m in exploitability.list_modules()
    ]
    return {"modules": mods, "active_execution_enabled": False,
            "note": "Assessment is analytical only. Active checks and proof execution are "
                    "gated by separate flags, plans, attestations, approvals and lab gates."}


@router.get("/api/issues/{issue_id}/exploitability")
def issue_exploitability(issue_id: str, user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)) -> list[dict]:
    """Offline assessments for an issue — per-prerequisite state and derived
    eligibility. ELIGIBLE_FOR_PROOF means a plan may be requested, never that
    execution is authorized."""
    _assessment_enabled()
    issue = _issue_or_404(db, user, issue_id)
    rows = db.execute(
        select(ExploitabilityAssessment).where(ExploitabilityAssessment.issue_id == issue.id)
    ).scalars().all()
    return [{
        "module_id": a.module_id, "module_admission_state": a.module_admission_state,
        "eligibility": a.eligibility, "prerequisites": a.prerequisites,
        "expected_effect": a.expected_effect, "next_action": a.next_action,
        "freshness_deadline": a.freshness_deadline, "assessment_version": a.assessment_version,
        "assessed_at": a.assessed_at,
    } for a in rows]


@router.post("/api/proof/modules/{module_id:path}/dry-run",
             dependencies=[Depends(require_csrf)])
def proof_module_dry_run(module_id: str, body: DryRunBody,
                         user: User = Depends(get_current_user)) -> dict:
    """Validate a module's parameters/policy/cost without sending any target
    traffic. Purely a schema/policy check — it does not run the module."""
    _assessment_enabled()
    module = next((m for m in exploitability.list_modules()
                   if m.get("module_id") == module_id), None)
    if module is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "module not found")
    return exploitability.dry_run(module, body.params)


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
