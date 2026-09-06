"""Audit trail viewing and chain verification."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditEvent, Notification, User
from ..services import AuditService
from ..services.authorization_service import ROLE_ADMIN
from .deps import get_current_user, require_admin, require_csrf

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _event_dto(e: AuditEvent) -> dict:
    return {
        "seq": e.seq,
        "ts": e.ts,
        "actor": e.actor,
        "action": e.action,
        "object_type": e.object_type,
        "object_id": e.object_id,
        "payload": e.payload,
        "prev_hash": e.prev_hash,
        "curr_hash": e.curr_hash,
    }


def _payload_matches(payload: dict, needle: str) -> bool:
    needle = needle.lower()
    for value in (payload or {}).values():
        if isinstance(value, str) and needle in value.lower():
            return True
        if isinstance(value, (int, float)) and needle == str(value).lower():
            return True
    return False


@router.get("/events")
def list_events(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
    action: list[str] | None = Query(default=None),
    q: str | None = Query(default=None, description="match object id, seq, or a payload value"),
    order: str = Query(default="desc", pattern=r"^(asc|desc)$"),
) -> list[dict]:
    events = db.execute(
        select(AuditEvent).order_by(AuditEvent.seq.asc())
    ).scalars().all()

    if user.role != ROLE_ADMIN:
        # Scanners see only events for their assigned targets (PRD 5.1).
        from ..models import Assignment

        target_ids = set(
            db.execute(
                select(Assignment.target_id).where(Assignment.user_id == user.id)
            ).scalars()
        )
        events = [
            e for e in events if e.object_type == "target" and e.object_id in target_ids
        ]

    if action:
        wanted = {a.upper() for a in action}
        events = [e for e in events if e.action.upper() in wanted]

    if q:
        needle = q.strip()
        events = [
            e for e in events
            if needle == str(e.seq)
            or needle.lower() in (e.object_id or "").lower()
            or _payload_matches(e.payload, needle)
        ]

    events.sort(key=lambda e: e.seq, reverse=(order == "desc"))
    return [_event_dto(e) for e in events[offset : offset + limit]]


@router.get("/actions")
def list_actions(user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)) -> list[str]:
    """Distinct action types, for building the filter UI."""
    rows = db.execute(select(AuditEvent.action).distinct()).scalars().all()
    return sorted(set(rows))


@router.post("/verify", dependencies=[Depends(require_csrf), Depends(require_admin)])
def verify_chain(admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    result = AuditService.verify_chain(db)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="AUDIT_VERIFICATION",
        object_type="audit", object_id="chain", payload=result,
    )
    if not result["ok"]:
        for a in db.execute(select(User).where(User.role == ROLE_ADMIN)).scalars():
            db.add(Notification(
                user_id=a.id, kind="AUDIT_VERIFICATION_FAILED",
                title="Audit chain verification FAILED",
                body=f"Chain broke at sequence {result.get('failed_seq')}: {result.get('reason')}",
            ))
    db.commit()
    return result
