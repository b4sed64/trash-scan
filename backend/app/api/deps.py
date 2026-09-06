"""Shared FastAPI dependencies: session auth, CSRF, role guards."""
from __future__ import annotations

import datetime as dt

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import SessionRecord, User
from ..services import AuthorizationService, PermissionDenied


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_aware(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


def get_current_session(request: Request, db: Session = Depends(get_db)) -> SessionRecord:
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    record = db.get(SessionRecord, token)
    if record is None or record.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")

    now = _utcnow()
    idle_limit = dt.timedelta(minutes=settings.session_idle_minutes)
    abs_limit = dt.timedelta(hours=settings.session_absolute_hours)
    if now - _as_aware(record.last_seen_at) > idle_limit:
        record.revoked = True
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired (idle)")
    if now - _as_aware(record.created_at) > abs_limit:
        record.revoked = True
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        record.revoked = True
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account is disabled")

    record.last_seen_at = now
    db.commit()
    return record


def get_current_user(
    session: SessionRecord = Depends(get_current_session), db: Session = Depends(get_db)
) -> User:
    return db.get(User, session.user_id)


def require_csrf(request: Request, session: SessionRecord = Depends(get_current_session)) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    settings = get_settings()
    header = request.headers.get(settings.csrf_header_name)
    if not header or header != session.csrf_token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


def require_admin(user: User = Depends(get_current_user)) -> User:
    try:
        AuthorizationService.require_admin(user)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.message) from exc
    return user
