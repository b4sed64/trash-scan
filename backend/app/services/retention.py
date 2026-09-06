"""Retention cleanup (PRD §17).

  * Operational logs: 7 days.
  * Dashboard notifications: 7 days after they were read.
  * Audit events: never deleted here (or anywhere in the application).
  * Targets, results and reports: only removed by explicit administrator deletion.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import Notification, OperationalLog
from .audit_service import AuditService

OPLOG_DAYS = 7
NOTIFICATION_DAYS_AFTER_READ = 7


def sweep(db: Session) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    oplog_cutoff = now - dt.timedelta(days=OPLOG_DAYS)
    notif_cutoff = now - dt.timedelta(days=NOTIFICATION_DAYS_AFTER_READ)

    oplogs = db.execute(
        delete(OperationalLog).where(OperationalLog.ts < oplog_cutoff)
    ).rowcount or 0
    notifs = db.execute(
        delete(Notification).where(
            Notification.read_at.is_not(None), Notification.read_at < notif_cutoff
        )
    ).rowcount or 0

    if oplogs or notifs:
        AuditService.append(
            db, actor="system:retention", action="RETENTION_CLEANUP",
            object_type="retention", object_id="",
            payload={"operational_logs_deleted": oplogs, "notifications_deleted": notifs},
        )
    db.commit()
    return {"operational_logs_deleted": oplogs, "notifications_deleted": notifs}
