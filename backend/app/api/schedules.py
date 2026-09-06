"""Passive schedules (PRD §11.5).

Phase 2 covers passive recurring schedules only. A scanner may create one for an
assigned target; an administrator manages all. Active schedules (with the
approval-per-occurrence workflow) arrive in Phase 3.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Schedule, ScheduleOccurrence, User
from ..services import AuditService, AuthorizationService
from ..services.authorization_service import PermissionDenied, ROLE_ADMIN
from ..services.schedule_service import compute_options_hash, next_run_after
from .deps import get_current_user, require_csrf

router = APIRouter(tags=["schedules"])


class ScheduleCreate(BaseModel):
    profile: str = Field(default="PASSIVE", pattern=r"^PASSIVE$")
    recurrence: str = Field(pattern=r"^(INTERVAL|DAILY)$")
    interval_minutes: int | None = Field(default=None, ge=15, le=10080)
    at_time: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    timezone: str = "UTC"
    overlap_policy: str = Field(default="SKIP", pattern=r"^(SKIP|ALLOW)$")

    @model_validator(mode="after")
    def _check(self):
        if self.recurrence == "INTERVAL" and not self.interval_minutes:
            raise ValueError("interval_minutes is required for INTERVAL schedules")
        if self.recurrence == "DAILY" and not self.at_time:
            raise ValueError("at_time is required for DAILY schedules")
        return self


class ScheduleUpdate(BaseModel):
    enabled: bool


def _access_or_404(db: Session, user: User, target_id: str):
    try:
        return AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc


def _dto(s: Schedule) -> dict:
    return {
        "id": s.id, "target_id": s.target_id, "profile": s.profile,
        "classification": s.classification, "recurrence": s.recurrence,
        "interval_minutes": s.interval_minutes, "at_time": s.at_time, "timezone": s.timezone,
        "enabled": s.enabled, "overlap_policy": s.overlap_policy,
        "next_run_at": s.next_run_at, "last_run_at": s.last_run_at,
        "created_by_id": s.created_by_id, "created_at": s.created_at,
    }


def _owned_or_admin(user: User, s: Schedule) -> None:
    if user.role != ROLE_ADMIN and s.created_by_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your schedule")


@router.get("/api/targets/{target_id}/schedules")
def list_schedules(target_id: str, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> list[dict]:
    _access_or_404(db, user, target_id)
    rows = db.execute(
        select(Schedule).where(Schedule.target_id == target_id).order_by(Schedule.created_at.desc())
    ).scalars().all()
    return [_dto(s) for s in rows]


@router.post("/api/targets/{target_id}/schedules", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_schedule(target_id: str, body: ScheduleCreate, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    target = _access_or_404(db, user, target_id)
    if not target.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, "target is archived")

    schedule = Schedule(
        target_id=target.id, created_by_id=user.id, profile="PASSIVE", classification="PASSIVE",
        recurrence=body.recurrence, interval_minutes=body.interval_minutes,
        at_time=body.at_time, timezone=body.timezone, overlap_policy=body.overlap_policy,
        options={}, enabled=True, created_at=dt.datetime.now(dt.timezone.utc),
    )
    schedule.options_hash = compute_options_hash(schedule)
    schedule.next_run_at = next_run_after(schedule, dt.datetime.now(dt.timezone.utc))
    db.add(schedule)
    db.flush()
    AuditService.append(
        db, actor=f"user:{user.username}", action="SCHEDULE_CREATED",
        object_type="schedule", object_id=schedule.id,
        payload={"target_id": target.id, "profile": "PASSIVE", "recurrence": body.recurrence,
                 "interval_minutes": body.interval_minutes, "at_time": body.at_time,
                 "next_run_at": schedule.next_run_at.isoformat()},
    )
    db.commit()
    return _dto(schedule)


@router.patch("/api/schedules/{schedule_id}", dependencies=[Depends(require_csrf)])
def update_schedule(schedule_id: str, body: ScheduleUpdate, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    s = db.get(Schedule, schedule_id)
    if s is None or not AuthorizationService.can_view_target(db, user, s.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    _owned_or_admin(user, s)
    s.enabled = body.enabled
    if body.enabled and s.next_run_at is None:
        s.next_run_at = next_run_after(s, dt.datetime.now(dt.timezone.utc))
    AuditService.append(
        db, actor=f"user:{user.username}",
        action="SCHEDULE_ENABLED" if body.enabled else "SCHEDULE_DISABLED",
        object_type="schedule", object_id=s.id, payload={},
    )
    db.commit()
    return _dto(s)


@router.delete("/api/schedules/{schedule_id}", dependencies=[Depends(require_csrf)])
def delete_schedule(schedule_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    s = db.get(Schedule, schedule_id)
    if s is None or not AuthorizationService.can_view_target(db, user, s.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    _owned_or_admin(user, s)
    db.delete(s)
    AuditService.append(
        db, actor=f"user:{user.username}", action="SCHEDULE_DELETED",
        object_type="schedule", object_id=schedule_id, payload={"target_id": s.target_id},
    )
    db.commit()
    return {"ok": True}


@router.get("/api/schedules/{schedule_id}/occurrences")
def list_occurrences(schedule_id: str, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)) -> list[dict]:
    s = db.get(Schedule, schedule_id)
    if s is None or not AuthorizationService.can_view_target(db, user, s.target_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    rows = db.execute(
        select(ScheduleOccurrence).where(ScheduleOccurrence.schedule_id == schedule_id)
        .order_by(ScheduleOccurrence.scheduled_for.desc()).limit(100)
    ).scalars().all()
    return [
        {
            "id": o.id, "scheduled_for": o.scheduled_for, "state": o.state,
            "execution_id": o.execution_id, "note": o.note, "created_at": o.created_at,
        }
        for o in rows
    ]
