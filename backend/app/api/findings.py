"""Findings and scan comparison (PRD §9.3, §11.4, §15)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, FindingSighting, ScanComparison, ScanExecution, User
from ..services import AuthorizationService
from ..services.authorization_service import PermissionDenied
from ..services.findings import severity_rank
from .deps import get_current_user

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
