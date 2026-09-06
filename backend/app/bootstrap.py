"""Idempotent startup tasks: ensure schema and seed immutable built-in rules."""
from __future__ import annotations

from sqlalchemy import select

from .db import Base, SessionLocal, engine
from .models import DenyRule
from .services.scope_service import BUILTIN_DENY_RULES


def create_all() -> None:
    """Create tables when running without Alembic (tests, quick local start)."""
    Base.metadata.create_all(bind=engine)


def seed_builtin_deny_rules() -> None:
    with SessionLocal() as db:
        existing = {
            (r.rule_type, r.value)
            for r in db.execute(select(DenyRule).where(DenyRule.is_builtin.is_(True))).scalars()
        }
        added = False
        for spec in BUILTIN_DENY_RULES:
            if (spec.rule_type, spec.value) in existing:
                continue
            db.add(DenyRule(
                rule_type=spec.rule_type, value=spec.value, category=spec.category,
                is_builtin=True,
            ))
            added = True
        if added:
            db.commit()
