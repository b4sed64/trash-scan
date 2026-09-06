"""Render report context to PDF (Jinja2 HTML + WeasyPrint) and persist artifacts."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Report
from ..services.audit_service import AuditService
from . import csv_export
from .data import gather_execution_report, gather_target_report

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)


def _report_dir() -> Path:
    path = Path(get_settings().result_root).parent / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def render_pdf(context: dict) -> bytes:
    from weasyprint import HTML  # imported lazily so tests without libpango still collect

    html = _env.get_template("report.html.j2").render(**context)
    return HTML(string=html).write_pdf()


def _persist(db: Session, *, kind: str, fmt: str, target_id: str | None,
             execution_id: str | None, requester_id: str | None, requester: str,
             filename: str, data: bytes, params: dict) -> Report:
    out_dir = _report_dir()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stored_name = f"{stamp}_{filename}"
    (out_dir / stored_name).write_bytes(data)

    report = Report(
        kind=kind, format=fmt, target_id=target_id, execution_id=execution_id,
        requested_by_id=requester_id, filename=filename, path=str(out_dir / stored_name),
        size_bytes=len(data), params=params,
    )
    db.add(report)
    db.flush()
    AuditService.append(
        db, actor=f"user:{requester}", action="REPORT_GENERATED",
        object_type="report", object_id=report.id,
        payload={"kind": kind, "format": fmt, "target_id": target_id,
                 "execution_id": execution_id, "size_bytes": len(data)},
    )
    return report


def generate_target_pdf(db: Session, target_id: str, *, requester_id: str,
                        requester: str) -> Report:
    ctx = gather_target_report(db, target_id, requester=requester)
    data = render_pdf(ctx)
    label = ctx["target"]["value"].replace("/", "_").replace(":", "_")
    return _persist(db, kind="TARGET", fmt="PDF", target_id=target_id, execution_id=None,
                    requester_id=requester_id, requester=requester,
                    filename=f"trashscan_{label}.pdf", data=data, params={})


def generate_execution_pdf(db: Session, execution_id: str, target_id: str, *,
                           requester_id: str, requester: str) -> Report:
    ctx = gather_execution_report(db, execution_id, requester=requester)
    data = render_pdf(ctx)
    return _persist(db, kind="EXECUTION", fmt="PDF", target_id=target_id,
                    execution_id=execution_id, requester_id=requester_id, requester=requester,
                    filename=f"trashscan_execution_{execution_id[:8]}.pdf", data=data, params={})


def generate_csv_zip(db: Session, target_ids: list[str], *, requester_id: str, requester: str,
                     primary_target_id: str | None = None) -> Report:
    data = csv_export.build_csv_zip(db, target_ids)
    label = (csv_export.target_label(db, primary_target_id) if primary_target_id else "all")
    return _persist(db, kind="TARGET", fmt="CSV_ZIP", target_id=primary_target_id,
                    execution_id=None, requester_id=requester_id, requester=requester,
                    filename=f"trashscan_{label}_csv.zip", data=data,
                    params={"target_ids": target_ids})


def read_report_bytes(report: Report) -> bytes:
    return Path(report.path).read_bytes() if os.path.exists(report.path) else b""
