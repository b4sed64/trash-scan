"""Report generation and export (PRD §16, RPT-01..06)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Report, ScanExecution, User
from ..reports import renderer
from ..services import AuditService, AuthorizationService
from ..services.authorization_service import PermissionDenied, ROLE_ADMIN
from .deps import get_current_user, require_csrf

router = APIRouter(tags=["reports"])


class ReportRequest(BaseModel):
    format: str = Field(pattern=r"^(PDF|CSV_ZIP)$")
    execution_id: str | None = None


_MIME = {"PDF": "application/pdf", "CSV_ZIP": "application/zip"}


def _access_or_404(db: Session, user: User, target_id: str):
    try:
        return AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc


def _dto(r: Report) -> dict:
    return {
        "id": r.id, "kind": r.kind, "format": r.format, "target_id": r.target_id,
        "execution_id": r.execution_id, "filename": r.filename, "size_bytes": r.size_bytes,
        "created_at": r.created_at, "requested_by_id": r.requested_by_id,
    }


def _may_view_report(db: Session, user: User, r: Report) -> bool:
    if user.role == ROLE_ADMIN:
        return True
    if r.target_id and AuthorizationService.can_view_target(db, user, r.target_id):
        return True
    return r.requested_by_id == user.id


@router.post("/api/targets/{target_id}/reports", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_target_report(target_id: str, body: ReportRequest,
                         user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)) -> dict:
    _access_or_404(db, user, target_id)

    if body.format == "PDF" and body.execution_id:
        ex = db.get(ScanExecution, body.execution_id)
        if ex is None or ex.target_id != target_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "execution not found for this target")
        report = renderer.generate_execution_pdf(
            db, body.execution_id, target_id, requester_id=user.id, requester=user.username)
    elif body.format == "PDF":
        report = renderer.generate_target_pdf(
            db, target_id, requester_id=user.id, requester=user.username)
    else:
        report = renderer.generate_csv_zip(
            db, [target_id], requester_id=user.id, requester=user.username,
            primary_target_id=target_id)
    db.commit()
    return _dto(db.get(Report, report.id))


@router.post("/api/reports/csv", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_csv_export(user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)) -> dict:
    """CSV export across every target the requester may access (RPT-03/04)."""
    target_ids = [t.id for t in AuthorizationService.visible_targets(db, user)]
    report = renderer.generate_csv_zip(
        db, target_ids, requester_id=user.id, requester=user.username)
    db.commit()
    return _dto(db.get(Report, report.id))


@router.get("/api/reports")
def list_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(Report).order_by(Report.created_at.desc()).limit(200)).scalars().all()
    return [_dto(r) for r in rows if _may_view_report(db, user, r)]


@router.get("/api/targets/{target_id}/reports")
def list_target_reports(target_id: str, user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Report).where(Report.target_id == target_id).order_by(Report.created_at.desc())
    ).scalars().all()
    return [_dto(r) for r in rows]


@router.get("/api/reports/{report_id}/download", dependencies=[Depends(require_csrf)])
def download_report(report_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> Response:
    r = db.get(Report, report_id)
    if r is None or not _may_view_report(db, user, r):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    data = renderer.read_report_bytes(r)
    if not data:
        raise HTTPException(status.HTTP_410_GONE, "report artifact no longer on disk")
    AuditService.append(
        db, actor=f"user:{user.username}", action="REPORT_EXPORTED",
        object_type="report", object_id=r.id,
        payload={"format": r.format, "target_id": r.target_id, "bytes": len(data)},
    )
    db.commit()
    return Response(
        content=data, media_type=_MIME.get(r.format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{r.filename}"'},
    )
