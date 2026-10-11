"""Issue review, remediation workflow and risk exceptions (PRD v2 §12, Phase 12).

Three independent dimensions on a canonical issue: scan observation/change
(already on findings), analyst validation, and remediation workflow. Validation
confirms the stated condition/applicability, never exploitability. Closure
requires administrator authority plus a qualifying negative *or* recorded manual
evidence — a negative scan alone can be produced by an incomplete stage, so it
is never sufficient by itself (that guard lives in the coverage-gated comparison
from Phase 8; here we require the issue to actually be NOT_OBSERVED or an explicit
manual-evidence flag).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Issue, Notification, RiskException, User
from .audit_service import AuditService

VALIDATION_STATES = {"UNREVIEWED", "VALIDATED", "FALSE_POSITIVE", "INCONCLUSIVE"}
REMEDIATION_STATES = {"OPEN", "IN_PROGRESS", "MITIGATED", "RESOLVED_VERIFIED", "RISK_ACCEPTED"}
# Dispositions excluded from the default active count but retained in history/exports.
EXCLUDED_REMEDIATION = {"RESOLVED_VERIFIED", "RISK_ACCEPTED"}
EXCLUDED_VALIDATION = {"FALSE_POSITIVE"}


class ReviewError(ValueError):
    """A review transition precondition was not met."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def set_validation(db: Session, issue: Issue, state: str, actor: str, reason: str = "") -> Issue:
    if state not in VALIDATION_STATES:
        raise ReviewError(f"invalid validation state {state!r}")
    issue.validation_state = state
    AuditService.append(db, actor=actor, action="ISSUE_VALIDATION_SET",
                        object_type="issue", object_id=issue.id,
                        payload={"validation_state": state, "reason": reason[:512]})
    return issue


def assign(db: Session, issue: Issue, *, owner: str, due_date: dt.datetime | None,
           desired_state: str, plan: str, actor: str) -> Issue:
    issue.owner = owner[:128]
    issue.due_date = due_date
    issue.desired_state = desired_state[:256]
    issue.remediation_plan = plan
    if issue.remediation_state == "OPEN":
        issue.remediation_state = "IN_PROGRESS"
    AuditService.append(db, actor=actor, action="ISSUE_ASSIGNED",
                        object_type="issue", object_id=issue.id,
                        payload={"owner": issue.owner, "desired_state": issue.desired_state,
                                 "due_date": due_date.isoformat() if due_date else None})
    return issue


def set_mitigated(db: Session, issue: Issue, actor: str, note: str = "") -> Issue:
    # MITIGATED reduces impact without asserting the underlying condition is gone.
    issue.remediation_state = "MITIGATED"
    AuditService.append(db, actor=actor, action="ISSUE_MITIGATED",
                        object_type="issue", object_id=issue.id, payload={"note": note[:512]})
    return issue


def accept_risk(db: Session, issue: Issue, *, reason: str, scope: str, controls: str,
                expires_at: dt.datetime, admin: User) -> RiskException:
    if not reason.strip():
        raise ReviewError("a risk acceptance requires a reason")
    if expires_at is None:
        raise ReviewError("a risk acceptance requires an expiry/review date")
    exc = RiskException(issue_id=issue.id, reason=reason[:512], scope=scope[:256],
                        compensating_controls=controls[:512], created_by_id=admin.id,
                        expires_at=expires_at, active=True)
    db.add(exc)
    issue.remediation_state = "RISK_ACCEPTED"
    AuditService.append(db, actor=f"user:{admin.username}", action="RISK_ACCEPTED",
                        object_type="issue", object_id=issue.id,
                        payload={"reason": exc.reason, "scope": exc.scope,
                                 "expires_at": expires_at.isoformat()})
    return exc


def verify_closure(db: Session, issue: Issue, *, admin: User, reason: str, evidence_ref: str,
                   manually_verified: bool) -> Issue:
    """Mark RESOLVED_VERIFIED. Requires either a qualifying negative (the issue is
    currently NOT_OBSERVED from a coverage-gated comparison) or explicit recorded
    manual evidence — never a bare clean scan."""
    if not reason.strip():
        raise ReviewError("closure requires a reason")
    if manually_verified:
        if not evidence_ref.strip():
            raise ReviewError("manual verification requires an evidence reference")
        method = "MANUAL"
    else:
        if issue.status != "NOT_OBSERVED":
            raise ReviewError(
                "cannot verify closure: no qualifying negative retest (issue is not "
                "NOT_OBSERVED); run a compatible rescan or record manual evidence")
        method = "RETEST_NEGATIVE"
    issue.remediation_state = "RESOLVED_VERIFIED"
    issue.reopened = False
    issue.closed_by_id = admin.id
    issue.closed_at = _now()
    issue.closure_reason = reason[:512]
    issue.closure_evidence_ref = evidence_ref[:256]
    issue.verification_method = method
    issue.manually_verified = manually_verified
    AuditService.append(db, actor=f"user:{admin.username}", action="ISSUE_CLOSED",
                        object_type="issue", object_id=issue.id,
                        payload={"reason": issue.closure_reason, "method": method,
                                 "evidence_ref": issue.closure_evidence_ref})
    return issue


def maybe_reopen(db: Session, issue: Issue) -> bool:
    """Called when a new occurrence is observed for an issue. If the issue was
    previously RESOLVED_VERIFIED, reopen it — preserving ownership and prior
    closure metadata — and notify administrators (§12.3.6)."""
    if issue.remediation_state != "RESOLVED_VERIFIED":
        return False
    issue.remediation_state = "OPEN"
    issue.reopened = True
    AuditService.append(db, actor="system:worker", action="ISSUE_REOPENED",
                        object_type="issue", object_id=issue.id,
                        payload={"issue_type": issue.issue_type,
                                 "prior_closed_at": issue.closed_at.isoformat() if issue.closed_at else None})
    for admin in db.execute(select(User).where(User.role == "ADMINISTRATOR")).scalars():
        db.add(Notification(user_id=admin.id, kind="ISSUE_REOPENED",
                            title="Verified issue reopened",
                            body=f"{issue.issue_type} on target {issue.target_id} was observed "
                                 f"again after verified closure."))
    return True


def expire_due_exceptions(db: Session) -> int:
    """Deactivate risk exceptions past their expiry so they resurface for review.
    Returns how many were expired."""
    now = _now()
    rows = db.execute(
        select(RiskException).where(RiskException.active.is_(True))
    ).scalars().all()
    n = 0
    for exc in rows:
        if exc.expires_at and exc.expires_at < now:
            exc.active = False
            n += 1
    return n
