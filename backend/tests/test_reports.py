"""Reports, CSV exports, retention and maintenance (PRD §16, §17, §12.6)."""
from __future__ import annotations

import datetime as dt
import io
import zipfile

import pytest

from app.models import (
    Asset,
    AuditEvent,
    Finding,
    Notification,
    OperationalLog,
    PrivateCidr,
    Report,
    Target,
    User,
)
from app.reports import csv_export
from app.reports.renderer import generate_csv_zip, generate_target_pdf, read_report_bytes
from app.security import hash_password
from app.services import retention


@pytest.fixture
def lab(db):
    admin = User(username="adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
                 is_active=True)
    db.add_all([admin, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.20", note="lab host")
    db.add(t)
    db.flush()
    db.add(Asset(target_id=t.id, kind="IP", value="10.10.5.20", source="dnsx", in_scope=True))
    db.add(Finding(
        target_id=t.id, fingerprint="fp1", source_tool="nuclei", rule_id="trashscan-x",
        severity="MEDIUM", name="Exposed thing", asset_value="10.10.5.20",
        evidence_summary="=cmd|' /C calc'!A0", status="OBSERVED",
    ))
    db.flush()
    db.commit()
    return {"admin": admin.id, "target": t.id}


# --- CSV formula injection (RPT-06) ------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("=1+1", "'=1+1"),
    ("+A1", "'+A1"),
    ("-2", "'-2"),
    ("@SUM(A1)", "'@SUM(A1)"),
    ("nginx/1.25", "nginx/1.25"),
    ("", ""),
])
def test_neutralize(raw, expected):
    assert csv_export.neutralize(raw) == expected


def test_csv_zip_has_all_four_files_and_escapes(db, lab):
    data = csv_export.build_csv_zip(db, [lab["target"]])
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert {"scans.csv", "assets.csv", "services.csv", "findings.csv"} <= set(zf.namelist())
    findings = zf.read("findings.csv").decode("utf-8-sig")
    assert "'=cmd" in findings  # the malicious evidence value was neutralized


# --- PDF report (RPT-01/02/04) ---------------------------------------
def test_target_pdf_is_generated_and_audited(db, lab):
    report = generate_target_pdf(db, lab["target"], requester_id=lab["admin"], requester="adm")
    db.commit()
    data = read_report_bytes(report)
    assert data[:5] == b"%PDF-"
    assert db.query(Report).count() == 1
    assert db.query(AuditEvent).filter(AuditEvent.action == "REPORT_GENERATED").count() == 1


def test_csv_report_row_persisted(db, lab):
    report = generate_csv_zip(db, [lab["target"]], requester_id=lab["admin"], requester="adm",
                              primary_target_id=lab["target"])
    db.commit()
    assert report.format == "CSV_ZIP"
    assert read_report_bytes(report)[:2] == b"PK"


# --- retention (PRD §17) -------------------------------------------
def test_retention_sweep_prunes_old_only(db, lab):
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)
    recent = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    db.add(OperationalLog(ts=old, level="INFO", message="old"))
    db.add(OperationalLog(ts=recent, level="INFO", message="recent"))
    db.add(Notification(user_id=lab["admin"], kind="X", title="old read", read_at=old))
    db.add(Notification(user_id=lab["admin"], kind="X", title="unread", read_at=None))
    db.commit()
    audit_before = db.query(AuditEvent).count()

    result = retention.sweep(db)
    assert result["operational_logs_deleted"] == 1
    assert result["notifications_deleted"] == 1
    assert db.query(OperationalLog).count() == 1
    assert db.query(Notification).filter(Notification.read_at.is_(None)).count() == 1
    # audit events are only ever appended, never deleted
    assert db.query(AuditEvent).count() >= audit_before
