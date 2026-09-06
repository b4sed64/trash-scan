"""Dashboard-only notifications (PRD 14.3)."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Notification, User
from .deps import get_current_user, require_csrf

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def list_notifications(user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)) -> dict:
    rows = db.execute(
        select(Notification)
        .where(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
        .limit(100)
    ).scalars().all()
    return {
        "unread": sum(1 for n in rows if n.read_at is None),
        "items": [
            {
                "id": n.id, "kind": n.kind, "title": n.title, "body": n.body,
                "created_at": n.created_at, "read_at": n.read_at,
            }
            for n in rows
        ],
    }


@router.post("/{notification_id}/read", dependencies=[Depends(require_csrf)])
def mark_read(notification_id: str, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)) -> dict:
    n = db.get(Notification, notification_id)
    if n is None or n.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if n.read_at is None:
        n.read_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/read-all", dependencies=[Depends(require_csrf)])
def mark_all_read(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    for n in db.execute(
        select(Notification).where(
            Notification.user_id == user.id, Notification.read_at.is_(None)
        )
    ).scalars():
        n.read_at = now
    db.commit()
    return {"ok": True}
