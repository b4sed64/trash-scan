"""Emergency stop endpoints (PRD §23.2). Administrator only."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import EmergencyStop, User
from ..services import emergency
from .deps import require_admin, require_csrf

router = APIRouter(prefix="/api/emergency-stop", tags=["emergency"],
                   dependencies=[Depends(require_admin)])


class StopRequest(BaseModel):
    scope: str = Field(default="ALL", pattern=r"^(ALL|SELECTED)$")
    execution_ids: list[str] = Field(default_factory=list)
    note: str = Field(default="", max_length=512)


def _dto(s: EmergencyStop) -> dict:
    return {
        "id": s.id, "state": s.state, "target_scope": s.target_scope,
        "execution_ids": s.execution_ids, "note": s.note,
        "requested_by_id": s.requested_by_id, "requested_at": s.requested_at,
        "cleared_by_id": s.cleared_by_id, "cleared_at": s.cleared_at,
    }


@router.get("")
def status_view(db: Session = Depends(get_db)) -> dict:
    active = emergency.active_stop(db)
    recent = db.execute(
        select(EmergencyStop).order_by(EmergencyStop.requested_at.desc()).limit(20)
    ).scalars().all()
    return {"active": _dto(active) if active else None, "history": [_dto(s) for s in recent]}


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_csrf)])
def request_stop(body: StopRequest, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)) -> dict:
    if emergency.active_stop(db):
        raise HTTPException(status.HTTP_409_CONFLICT, "an emergency stop is already active")
    stop = emergency.request_stop(
        db, actor=f"user:{admin.username}", requester_id=admin.id, scope=body.scope,
        execution_ids=body.execution_ids, note=body.note,
    )
    for a in db.execute(select(User).where(User.role == "ADMINISTRATOR")).scalars():
        from ..models import Notification

        db.add(Notification(user_id=a.id, kind="EMERGENCY_STOP",
                            title="Emergency stop requested",
                            body=f"{admin.username}: {body.note or 'no note'}"))
    db.commit()
    emergency.reconcile(db)
    db.commit()
    return _dto(db.get(EmergencyStop, stop.id))


@router.post("/{stop_id}/clear", dependencies=[Depends(require_csrf)])
def clear(stop_id: str, admin: User = Depends(require_admin),
          db: Session = Depends(get_db)) -> dict:
    stop = db.get(EmergencyStop, stop_id)
    if stop is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if stop.state == "CLEARED":
        raise HTTPException(status.HTTP_409_CONFLICT, "already cleared")
    emergency.clear_stop(db, stop, actor=f"user:{admin.username}", cleared_by=admin.id)
    db.commit()
    return _dto(db.get(EmergencyStop, stop_id))
