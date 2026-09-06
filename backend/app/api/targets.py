"""Target management, assignment, passive discovery and scope preview."""
from __future__ import annotations

import datetime as dt
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters import FakePassiveAdapter
from ..adapters.base import ScanInput
from ..constants import PUBLIC_TARGET_ATTESTATION
from ..db import get_db
from ..models import Assignment, Asset, Notification, Target, User
from ..services import AuditService, AuthorizationService, ScopeError, canonicalize_target
from ..services.authorization_service import PermissionDenied
from ..services.scope_db import evaluate_target_scope, load_private_cidrs
from .deps import get_current_user, require_admin, require_csrf

router = APIRouter(prefix="/api/targets", tags=["targets"])


# --- schemas --------------------------------------------------------------
class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=256)
    is_public: bool = False
    note: str = Field(default="", max_length=512)
    attestation_checkbox: bool = False
    attestation_text: str | None = None


class ConfirmDelete(BaseModel):
    confirm_value: str


class AssignRequest(BaseModel):
    user_id: str


# --- helpers -------------------------------------------------------------
def _within_any_cidr(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _target_dto(t: Target) -> dict:
    return {
        "id": t.id,
        "kind": t.kind,
        "value": t.value,
        "is_public": t.is_public,
        "is_active": t.is_active,
        "note": t.note,
        "created_at": t.created_at,
        "attestation": (
            {"text": t.attestation_text, "by": t.attested_by_id, "at": t.attested_at}
            if t.is_public
            else None
        ),
        "assignments": [a.user_id for a in t.assignments],
        "assets": [
            {
                "id": a.id,
                "kind": a.kind,
                "value": a.value,
                "source": a.source,
                "approved": a.approved,
                "in_scope": a.in_scope,
                "first_seen_at": a.first_seen_at,
                "last_seen_at": a.last_seen_at,
            }
            for a in sorted(t.assets, key=lambda x: (x.kind, x.value))
        ],
    }


def _access_or_404(db: Session, user: User, target_id: str) -> Target:
    try:
        return AuthorizationService.require_target_access(db, user, target_id)
    except PermissionDenied as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc


# --- endpoints ----------------------------------------------------------
@router.get("")
def list_targets(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [_target_dto(t) for t in AuthorizationService.visible_targets(db, user)]


@router.get("/{target_id}")
def get_target(target_id: str, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)) -> dict:
    return _target_dto(_access_or_404(db, user, target_id))


@router.post("", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_target(body: TargetCreate, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)) -> dict:
    try:
        kind, canonical = canonicalize_target(body.value)
    except ScopeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if db.execute(
        select(Target).where(Target.kind == kind, Target.value == canonical)
    ).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "target already exists")

    target = Target(
        kind=kind, value=canonical, is_public=body.is_public, note=body.note,
        created_by_id=admin.id,
    )

    if body.is_public:
        if (
            not body.attestation_checkbox
            or (body.attestation_text or "").strip() != PUBLIC_TARGET_ATTESTATION
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "public targets require the ownership checkbox and the exact attestation text",
            )
        target.attestation_checkbox = True
        target.attestation_text = PUBLIC_TARGET_ATTESTATION
        target.attested_by_id = admin.id
        target.attested_at = dt.datetime.now(dt.timezone.utc)

    db.add(target)
    db.flush()

    decision = evaluate_target_scope(db, target)
    if decision.matched_deny_rule:
        db.rollback()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"target rejected by policy: {decision.reason}",
        )

    AuditService.append(
        db, actor=f"user:{admin.username}", action="TARGET_CREATED",
        object_type="target", object_id=target.id,
        payload={"kind": kind, "value": canonical, "is_public": body.is_public},
    )
    if body.is_public:
        AuditService.append(
            db, actor=f"user:{admin.username}", action="PUBLIC_TARGET_ATTESTED",
            object_type="target", object_id=target.id,
            payload={"attestation": PUBLIC_TARGET_ATTESTATION},
        )
        for a in db.execute(select(User).where(User.role == "ADMINISTRATOR")).scalars():
            db.add(Notification(
                user_id=a.id, kind="PUBLIC_TARGET_ADDED", title="Public target added",
                body=f"{admin.username} added public target {canonical}",
            ))
    db.commit()
    return _target_dto(target)


@router.post("/{target_id}/archive", dependencies=[Depends(require_csrf)])
def archive_target(target_id: str, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    target.is_active = False
    AuditService.append(
        db, actor=f"user:{admin.username}", action="TARGET_ARCHIVED",
        object_type="target", object_id=target.id, payload={"value": target.value},
    )
    db.commit()
    return _target_dto(target)


@router.post("/{target_id}/delete", dependencies=[Depends(require_csrf)])
def delete_target(target_id: str, body: ConfirmDelete, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if body.confirm_value != target.value:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "confirmation value must exactly match the target value",
        )
    asset_count = len(target.assets)
    assignment_count = len(target.assignments)
    value = target.value
    db.delete(target)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="TARGET_DELETED",
        object_type="target", object_id=target_id,
        payload={
            "value": value, "assets_removed": asset_count,
            "assignments_removed": assignment_count,
        },
    )
    db.commit()
    return {"ok": True, "removed": {"assets": asset_count, "assignments": assignment_count}}


@router.post("/{target_id}/assignments", dependencies=[Depends(require_csrf)])
def assign_target(target_id: str, body: AssignRequest, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    scanner = db.get(User, body.user_id)
    if scanner is None or scanner.role != "SCANNER":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "user is not a scanner")
    if db.execute(
        select(Assignment).where(
            Assignment.target_id == target_id, Assignment.user_id == body.user_id
        )
    ).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "already assigned")
    db.add(Assignment(target_id=target_id, user_id=body.user_id, created_by_id=admin.id))
    AuditService.append(
        db, actor=f"user:{admin.username}", action="ASSIGNMENT_CREATED",
        object_type="target", object_id=target_id, payload={"user_id": body.user_id},
    )
    db.add(Notification(
        user_id=body.user_id, kind="ASSIGNMENT_CREATED", title="Target assigned",
        body=f"You were assigned to {target.value}",
    ))
    db.commit()
    return _target_dto(target)


@router.delete("/{target_id}/assignments/{user_id}", dependencies=[Depends(require_csrf)])
def unassign_target(target_id: str, user_id: str, admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)) -> dict:
    assignment = db.execute(
        select(Assignment).where(
            Assignment.target_id == target_id, Assignment.user_id == user_id
        )
    ).scalar_one_or_none()
    if assignment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assignment not found")
    db.delete(assignment)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="ASSIGNMENT_REMOVED",
        object_type="target", object_id=target_id, payload={"user_id": user_id},
    )
    db.commit()
    return _target_dto(db.get(Target, target_id))


@router.get("/{target_id}/scope-preview")
def scope_preview(target_id: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)) -> dict:
    target = _access_or_404(db, user, target_id)
    return evaluate_target_scope(db, target).as_audit_payload()


@router.post("/{target_id}/passive-scan", dependencies=[Depends(require_csrf)])
def run_passive_scan(target_id: str, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)) -> dict:
    target = _access_or_404(db, user, target_id)
    if not target.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, "target is archived")

    result = FakePassiveAdapter().run(ScanInput(target.kind, target.value, "PASSIVE"))
    if not result.ok:
        AuditService.append(
            db, actor=f"user:{user.username}", action="PASSIVE_SCAN_FAILED",
            object_type="target", object_id=target.id, payload={"stderr": result.stderr[:500]},
        )
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "passive discovery failed")

    private_cidrs = load_private_cidrs(db)
    now = dt.datetime.now(dt.timezone.utc)
    added = updated = 0
    for disc in result.assets:
        in_scope = disc.kind == "IP" and _within_any_cidr(disc.value, private_cidrs)
        existing = db.execute(
            select(Asset).where(
                Asset.target_id == target.id,
                Asset.kind == disc.kind,
                Asset.value == disc.value,
            )
        ).scalar_one_or_none()
        if existing:
            existing.last_seen_at = now
            existing.in_scope = in_scope
            updated += 1
        else:
            db.add(Asset(
                target_id=target.id, kind=disc.kind, value=disc.value, source=disc.source,
                in_scope=in_scope, approved=False, first_seen_at=now, last_seen_at=now,
            ))
            added += 1

    AuditService.append(
        db, actor=f"user:{user.username}", action="PASSIVE_SCAN_COMPLETED",
        object_type="target", object_id=target.id,
        payload={
            "tool": result.tool, "tool_version": result.tool_version,
            "assets_added": added, "assets_updated": updated,
        },
    )
    db.add(Notification(
        user_id=user.id, kind="SCAN_COMPLETED", title="Passive discovery completed",
        body=(
            f"{added} new / {updated} updated assets for {target.value}. "
            "Discovered assets are unapproved and never inherit authorization."
        ),
    ))
    db.commit()
    return _target_dto(target)
