"""Normalized CSV exports (PRD §16.2, RPT-03 / RPT-06).

Cells whose value came from a target or a scanner tool and begin with a
spreadsheet formula character are neutralized so that opening the file cannot
execute a formula.
"""
from __future__ import annotations

import csv
import io
import zipfile

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, Finding, ScanExecution, Service, Target

_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r", "\n")


def neutralize(value) -> str:
    """Prefix formula-leading untrusted values with a single quote."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _FORMULA_LEADERS:
        return "'" + text
    return text


def _write_csv(header: list[str], rows: list[list]) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([neutralize(c) for c in row])
    return buf.getvalue().encode("utf-8-sig")


def scans_csv(db: Session, target_ids: list[str]) -> bytes:
    header = ["execution_id", "target_id", "profile", "classification", "state", "partial",
              "created_at", "started_at", "finished_at", "parser_version", "template_set_hash"]
    rows = []
    for e in db.execute(
        select(ScanExecution).where(ScanExecution.target_id.in_(target_ids or ["__none__"]))
        .order_by(ScanExecution.created_at)
    ).scalars():
        rows.append([e.id, e.target_id, e.profile, e.classification, e.state, e.partial,
                     e.created_at, e.started_at, e.finished_at, e.parser_version,
                     e.template_set_hash])
    return _write_csv(header, rows)


def assets_csv(db: Session, target_ids: list[str]) -> bytes:
    header = ["asset_id", "target_id", "kind", "value", "source", "in_private_scope",
              "approved", "first_seen_at", "last_seen_at"]
    rows = []
    for a in db.execute(
        select(Asset).where(Asset.target_id.in_(target_ids or ["__none__"]))
        .order_by(Asset.target_id, Asset.value)
    ).scalars():
        rows.append([a.id, a.target_id, a.kind, a.value, a.source, a.in_scope, a.approved,
                     a.first_seen_at, a.last_seen_at])
    return _write_csv(header, rows)


def services_csv(db: Session, target_ids: list[str]) -> bytes:
    header = ["service_id", "target_id", "asset_id", "port", "protocol", "state", "product",
              "version", "confidence", "first_seen_at", "last_seen_at"]
    rows = []
    for s in db.execute(
        select(Service).where(Service.target_id.in_(target_ids or ["__none__"]))
        .order_by(Service.target_id, Service.port)
    ).scalars():
        rows.append([s.id, s.target_id, s.asset_id, s.port, s.protocol, s.state, s.product,
                     s.version, s.confidence, s.first_seen_at, s.last_seen_at])
    return _write_csv(header, rows)


def findings_csv(db: Session, target_ids: list[str]) -> bytes:
    header = ["finding_id", "target_id", "source_tool", "rule_id", "template_hash", "severity",
              "name", "asset", "port", "status", "evidence_summary", "first_seen_at",
              "last_seen_at", "note"]
    rows = []
    for f in db.execute(
        select(Finding).where(Finding.target_id.in_(target_ids or ["__none__"]))
        .order_by(Finding.target_id, Finding.severity)
    ).scalars():
        rows.append([f.id, f.target_id, f.source_tool, f.rule_id, f.template_hash, f.severity,
                     f.name, f.asset_value, f.port, f.status, f.evidence_summary,
                     f.first_seen_at, f.last_seen_at,
                     "automated indicator - requires human validation"])
    return _write_csv(header, rows)


def build_csv_zip(db: Session, target_ids: list[str]) -> bytes:
    files = {
        "scans.csv": scans_csv(db, target_ids),
        "assets.csv": assets_csv(db, target_ids),
        "services.csv": services_csv(db, target_ids),
        "findings.csv": findings_csv(db, target_ids),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        zf.writestr("README.txt",
                    b"Trash Scan CSV export.\r\n"
                    b"Automated findings are indicators that require human validation.\r\n"
                    b"Values beginning with = + - @ have been prefixed with ' to prevent "
                    b"spreadsheet formula execution.\r\n")
    return buf.getvalue()


def target_label(db: Session, target_id: str) -> str:
    t = db.get(Target, target_id)
    return (t.value if t else target_id).replace("/", "_").replace(":", "_")
