"""Structured operational logging (PRD §31).

Operational logs carry target / execution / stage / correlation ids for
debugging. They are retained for seven days and are never a source of truth for
authorization or audit history.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import OperationalLog


def log(db: Session, level: str, message: str, *, target_id: str | None = None,
        execution_id: str | None = None, stage_id: str | None = None,
        correlation_id: str | None = None) -> None:
    db.add(OperationalLog(
        level=level, message=message[:2000], target_id=target_id, execution_id=execution_id,
        stage_id=stage_id, correlation_id=correlation_id,
    ))
