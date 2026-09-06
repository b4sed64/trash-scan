"""AuthorizationService — deny-by-default role and assignment checks.

Every API and worker path must call these helpers; hidden UI controls are not
authorization (PRD 5.2 / AUTH-02). The service raises :class:`PermissionDenied`
so callers cannot accidentally treat a falsy return as "allowed".
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Assignment, Target, User

ROLE_ADMIN = "ADMINISTRATOR"
ROLE_SCANNER = "SCANNER"


class PermissionDenied(Exception):
    def __init__(self, message: str = "not authorized"):
        super().__init__(message)
        self.message = message


class AuthorizationService:
    @staticmethod
    def is_admin(user: User) -> bool:
        return user.role == ROLE_ADMIN

    @staticmethod
    def require_admin(user: User) -> None:
        if user.role != ROLE_ADMIN:
            raise PermissionDenied("administrator role required")

    @staticmethod
    def is_assigned(db: Session, user: User, target_id: str) -> bool:
        row = db.execute(
            select(Assignment.id).where(
                Assignment.user_id == user.id, Assignment.target_id == target_id
            )
        ).first()
        return row is not None

    @staticmethod
    def can_view_target(db: Session, user: User, target_id: str) -> bool:
        if user.role == ROLE_ADMIN:
            return True
        return AuthorizationService.is_assigned(db, user, target_id)

    @staticmethod
    def require_target_access(db: Session, user: User, target_id: str) -> Target:
        target = db.get(Target, target_id)
        if target is None:
            # Do not disclose existence to unauthorised scanners.
            raise PermissionDenied("target not found or not accessible")
        if not AuthorizationService.can_view_target(db, user, target_id):
            raise PermissionDenied("target not found or not accessible")
        return target

    @staticmethod
    def visible_targets(db: Session, user: User) -> list[Target]:
        if user.role == ROLE_ADMIN:
            return list(db.execute(select(Target).order_by(Target.created_at.desc())).scalars())
        return list(
            db.execute(
                select(Target)
                .join(Assignment, Assignment.target_id == Target.id)
                .where(Assignment.user_id == user.id)
                .order_by(Target.created_at.desc())
            ).scalars()
        )
