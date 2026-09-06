"""Authentication endpoints: first-run setup, login, logout, session info."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import SessionRecord, User
from ..security import hash_password, new_csrf_token, new_session_token, verify_password
from ..services import AuditService
from ..services.authorization_service import ROLE_ADMIN
from .deps import get_current_session, get_current_user, require_csrf

router = APIRouter(prefix="/api/auth", tags=["auth"])


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_session_cookies(response: Response, token: str, csrf: str) -> None:
    s = get_settings()
    response.set_cookie(
        s.session_cookie_name, token, httponly=True, secure=s.session_cookie_secure,
        samesite="lax", path="/",
    )
    response.set_cookie(
        s.csrf_cookie_name, csrf, httponly=False, secure=s.session_cookie_secure,
        samesite="lax", path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(s.session_cookie_name, path="/")
    response.delete_cookie(s.csrf_cookie_name, path="/")


@router.get("/setup-status")
def setup_status(db: Session = Depends(get_db)) -> dict:
    count = db.execute(select(func.count()).select_from(User)).scalar_one()
    return {"needs_setup": count == 0}


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def first_run_setup(body: SetupRequest, request: Request, response: Response,
                    db: Session = Depends(get_db)) -> dict:
    count = db.execute(select(func.count()).select_from(User)).scalar_one()
    if count != 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "setup has already been completed")

    user = User(
        username=body.username,
        role=ROLE_ADMIN,
        password_hash=hash_password(body.password),
        is_active=True,
    )
    db.add(user)
    db.flush()
    AuditService.append(
        db, actor=f"user:{user.username}", action="ACCOUNT_CREATED",
        object_type="user", object_id=user.id,
        payload={"role": ROLE_ADMIN, "via": "first_run_setup"},
    )
    AuditService.append(
        db, actor=f"user:{user.username}", action="AUTH_SUCCESS",
        object_type="user", object_id=user.id, payload={"ip": _client(request)},
    )

    token, csrf = new_session_token(), new_csrf_token()
    db.add(SessionRecord(id=token, user_id=user.id, csrf_token=csrf))
    db.commit()
    _set_session_cookies(response, token, csrf)
    return {"id": user.id, "username": user.username, "role": user.role, "csrf_token": csrf}


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)) -> dict:
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    ok = user is not None and verify_password(user.password_hash, body.password)

    if not ok or not user.is_active:
        AuditService.append(
            db, actor=f"username:{body.username}", action="AUTH_FAILURE",
            object_type="user", object_id=user.id if user else "",
            payload={"ip": _client(request), "reason": "bad_credentials_or_disabled"},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    token, csrf = new_session_token(), new_csrf_token()
    db.add(SessionRecord(id=token, user_id=user.id, csrf_token=csrf))
    AuditService.append(
        db, actor=f"user:{user.username}", action="AUTH_SUCCESS",
        object_type="user", object_id=user.id, payload={"ip": _client(request)},
    )
    db.commit()
    _set_session_cookies(response, token, csrf)
    return {"id": user.id, "username": user.username, "role": user.role, "csrf_token": csrf}


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(response: Response, session: SessionRecord = Depends(get_current_session),
           db: Session = Depends(get_db)) -> dict:
    session.revoked = True
    AuditService.append(
        db, actor=f"user:{session.user_id}", action="AUTH_LOGOUT",
        object_type="session", object_id=session.id, payload={},
    )
    db.commit()
    _clear_session_cookies(response)
    return {"ok": True}


@router.post("/change-password", dependencies=[Depends(require_csrf)])
def change_password(body: ChangePasswordRequest, request: Request,
                    session: SessionRecord = Depends(get_current_session),
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    if not verify_password(user.password_hash, body.current_password):
        AuditService.append(
            db, actor=f"user:{user.username}", action="AUTH_FAILURE",
            object_type="user", object_id=user.id,
            payload={"ip": _client(request), "reason": "change_password_bad_current"},
        )
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "new password must differ from the current one")

    user.password_hash = hash_password(body.new_password)
    # Invalidate every other session for this user; keep the caller's.
    db.query(SessionRecord).filter(
        SessionRecord.user_id == user.id,
        SessionRecord.id != session.id,
        SessionRecord.revoked.is_(False),
    ).update({"revoked": True})
    AuditService.append(
        db, actor=f"user:{user.username}", action="PASSWORD_CHANGED",
        object_type="user", object_id=user.id, payload={"ip": _client(request), "self": True},
    )
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user),
       session: SessionRecord = Depends(get_current_session)) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "csrf_token": session.csrf_token,
    }
