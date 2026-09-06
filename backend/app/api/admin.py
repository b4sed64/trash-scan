"""Administration: accounts, private scope, deny rules."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import DenyRule, PrivateCidr, SessionRecord, User
from ..security import hash_password
from ..services import AuditService
from ..services.scope_service import (
    DENY_CIDR,
    DENY_DOMAIN_EXACT,
    DENY_DOMAIN_SUFFIX,
    DENY_IP,
    canonicalize_domain,
)
from .deps import require_admin, require_csrf

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# --- accounts ----------------------------------------------------------
class AccountCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern=r"^(ADMINISTRATOR|SCANNER)$")


class AccountUpdate(BaseModel):
    is_active: bool


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


def _user_dto(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "role": u.role,
        "is_active": u.is_active, "created_at": u.created_at,
    }


@router.get("/accounts")
def list_accounts(db: Session = Depends(get_db)) -> list[dict]:
    return [_user_dto(u) for u in db.execute(select(User).order_by(User.username)).scalars()]


@router.post("/accounts", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_account(body: AccountCreate, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)) -> dict:
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    # New accounts are created disabled; an administrator enables them (PRD 5.2).
    user = User(
        username=body.username, role=body.role,
        password_hash=hash_password(body.password), is_active=False,
        created_by_id=admin.id,
    )
    db.add(user)
    db.flush()
    AuditService.append(
        db, actor=f"user:{admin.username}", action="ACCOUNT_CREATED",
        object_type="user", object_id=user.id,
        payload={"role": body.role, "is_active": False},
    )
    db.commit()
    return _user_dto(user)


@router.post("/accounts/{user_id}/reset-password", dependencies=[Depends(require_csrf)])
def reset_password(user_id: str, body: PasswordReset, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    user.password_hash = hash_password(body.new_password)
    # Force the account to re-authenticate everywhere (AUTH-04).
    db.execute(
        update(SessionRecord)
        .where(SessionRecord.user_id == user_id, SessionRecord.revoked.is_(False))
        .values(revoked=True)
    )
    AuditService.append(
        db, actor=f"user:{admin.username}", action="PASSWORD_RESET",
        object_type="user", object_id=user.id,
        payload={"target_user": user.username, "sessions_revoked": True},
    )
    db.commit()
    return {"ok": True}


@router.patch("/accounts/{user_id}", dependencies=[Depends(require_csrf)])
def update_account(user_id: str, body: AccountUpdate, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if user.id == admin.id and not body.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "you cannot disable your own account")

    user.is_active = body.is_active
    action = "ACCOUNT_ENABLED" if body.is_active else "ACCOUNT_DISABLED"
    if not body.is_active:
        # Invalidate active sessions (AUTH-04).
        db.execute(
            update(SessionRecord)
            .where(SessionRecord.user_id == user_id, SessionRecord.revoked.is_(False))
            .values(revoked=True)
        )
    AuditService.append(
        db, actor=f"user:{admin.username}", action=action,
        object_type="user", object_id=user.id, payload={},
    )
    db.commit()
    return _user_dto(user)


# --- private scope ---------------------------------------------------
class PrivateCidrCreate(BaseModel):
    cidr: str
    note: str = Field(default="", max_length=256)


@router.get("/private-cidrs")
def list_private_cidrs(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {"id": p.id, "cidr": p.cidr, "note": p.note, "created_at": p.created_at}
        for p in db.execute(select(PrivateCidr).order_by(PrivateCidr.cidr)).scalars()
    ]


@router.post("/private-cidrs", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def add_private_cidr(body: PrivateCidrCreate, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)) -> dict:
    try:
        net = ipaddress.ip_network(body.cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid CIDR") from exc
    if net.version != 4:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "IPv6 is not supported")
    if not net.is_private:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "only RFC1918 private ranges may be added as default scope",
        )
    canonical = str(net)
    if db.execute(
        select(PrivateCidr).where(PrivateCidr.cidr == canonical)
    ).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "range already configured")
    row = PrivateCidr(cidr=canonical, note=body.note, created_by_id=admin.id)
    db.add(row)
    db.flush()
    AuditService.append(
        db, actor=f"user:{admin.username}", action="PRIVATE_SCOPE_ADDED",
        object_type="private_cidr", object_id=row.id, payload={"cidr": canonical},
    )
    db.commit()
    return {"id": row.id, "cidr": row.cidr, "note": row.note, "created_at": row.created_at}


@router.delete("/private-cidrs/{cidr_id}", dependencies=[Depends(require_csrf)])
def remove_private_cidr(cidr_id: str, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)) -> dict:
    row = db.get(PrivateCidr, cidr_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    cidr = row.cidr
    db.delete(row)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="PRIVATE_SCOPE_REMOVED",
        object_type="private_cidr", object_id=cidr_id, payload={"cidr": cidr},
    )
    db.commit()
    return {"ok": True}


# --- deny rules ----------------------------------------------------
class DenyRuleCreate(BaseModel):
    rule_type: str = Field(pattern=r"^(DOMAIN_EXACT|DOMAIN_SUFFIX|IP|CIDR)$")
    value: str
    category: str = Field(default="CUSTOM", pattern=r"^(GOVERNMENT|MILITARY|HEALTHCARE|CUSTOM)$")


def _normalise_deny_value(rule_type: str, value: str) -> str:
    value = value.strip()
    if rule_type == DENY_DOMAIN_EXACT:
        return canonicalize_domain(value.lstrip("."))
    if rule_type == DENY_DOMAIN_SUFFIX:
        # Suffix rules are commonly a single label ("gov", "mil").
        return canonicalize_domain(value.lstrip("."), require_multilabel=False)
    if rule_type == DENY_IP:
        return str(ipaddress.ip_address(value))
    if rule_type == DENY_CIDR:
        return str(ipaddress.ip_network(value, strict=False))
    raise ValueError("unknown rule type")


@router.get("/deny-rules")
def list_deny_rules(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": r.id, "rule_type": r.rule_type, "value": r.value,
            "category": r.category, "is_builtin": r.is_builtin, "created_at": r.created_at,
        }
        for r in db.execute(
            select(DenyRule).order_by(DenyRule.is_builtin.desc(), DenyRule.value)
        ).scalars()
    ]


@router.post("/deny-rules", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def add_deny_rule(body: DenyRuleCreate, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)) -> dict:
    try:
        value = _normalise_deny_value(body.rule_type, body.value)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if db.execute(
        select(DenyRule).where(DenyRule.rule_type == body.rule_type, DenyRule.value == value)
    ).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "rule already exists")
    row = DenyRule(
        rule_type=body.rule_type, value=value, category=body.category,
        is_builtin=False, created_by_id=admin.id,
    )
    db.add(row)
    db.flush()
    AuditService.append(
        db, actor=f"user:{admin.username}", action="DENY_RULE_ADDED",
        object_type="deny_rule", object_id=row.id,
        payload={"rule_type": body.rule_type, "value": value, "category": body.category},
    )
    db.commit()
    return {
        "id": row.id, "rule_type": row.rule_type, "value": row.value,
        "category": row.category, "is_builtin": row.is_builtin, "created_at": row.created_at,
    }


@router.delete("/deny-rules/{rule_id}", dependencies=[Depends(require_csrf)])
def remove_deny_rule(rule_id: str, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)) -> dict:
    row = db.get(DenyRule, rule_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if row.is_builtin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "built-in government / military / healthcare rules cannot be removed",
        )
    payload = {"rule_type": row.rule_type, "value": row.value}
    db.delete(row)
    AuditService.append(
        db, actor=f"user:{admin.username}", action="DENY_RULE_REMOVED",
        object_type="deny_rule", object_id=rule_id, payload=payload,
    )
    db.commit()
    return {"ok": True}
