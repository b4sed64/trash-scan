"""Scan groups — a scan is one logical unit that may cover several targets.

Each target in a scan is one :class:`ScanExecution` sharing a ``scan_group_id``.
A single-target scan is a group of one. The group's state is derived from its
executions; there is no separate stored state.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ScanApproval, ScanExecution

TERMINAL = {"COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"}


def executions_for(db: Session, scan_id: str) -> list[ScanExecution]:
    """Return the executions of a scan, given a group id or a single execution id."""
    rows = db.execute(
        select(ScanExecution).where(ScanExecution.scan_group_id == scan_id)
        .order_by(ScanExecution.group_seq)
    ).scalars().all()
    if rows:
        return list(rows)
    single = db.get(ScanExecution, scan_id)
    return [single] if single is not None else []


def group_state(executions: list[ScanExecution]) -> str:
    """Aggregate a group's state from its executions."""
    states = [e.state for e in executions]
    if not states:
        return "UNKNOWN"
    if all(s in TERMINAL for s in states):
        uniq = set(states)
        if uniq == {"COMPLETED"}:
            return "COMPLETED"
        if uniq == {"CANCELLED"}:
            return "CANCELLED"
        if uniq == {"DENIED"}:
            return "DENIED"
        if uniq == {"EXPIRED"}:
            return "EXPIRED"
        if "COMPLETED" in uniq and uniq <= {"COMPLETED", "CANCELLED", "TIMED_OUT", "FAILED"}:
            return "PARTIAL"
        if "TIMED_OUT" in uniq:
            return "TIMED_OUT"
        if "FAILED" in uniq:
            return "FAILED"
        return "PARTIAL"
    for wanted in ("CANCELLING", "RUNNING", "QUEUED", "APPROVED", "AWAITING_APPROVAL", "DRAFT"):
        if wanted in states:
            return wanted
    return "RUNNING"


def approval_for(db: Session, scan_id: str, executions: list[ScanExecution]) -> ScanApproval | None:
    by_group = db.execute(
        select(ScanApproval).where(ScanApproval.scan_group_id == scan_id)
    ).scalars().first()
    if by_group is not None:
        return by_group
    ids = [e.id for e in executions]
    if not ids:
        return None
    return db.execute(
        select(ScanApproval).where(ScanApproval.execution_id.in_(ids))
        .order_by(ScanApproval.created_at.desc())
    ).scalars().first()
