"""Canonical issue identities and lossless backfill (PRD v2 §10, Phase 9).

A canonical :class:`Issue` groups the findings that describe the *same*
condition, including equivalent detectors from different tools. Equivalence is
**declared explicitly** — the default is to treat every ``(tool, rule_id)`` as
its own class (tool-qualified), so two detectors are only ever merged when we
have said they are the same. This is the safe direction: an un-declared pair
stays separate rather than being wrongly fused.

The canonical layer is a projection of the existing Finding/FindingSighting
rows; it never mutates them, so ``backfill_all`` is lossless and the migration
that adds the tables is fully reversible.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, FindingSighting, Issue, Occurrence, ScanExecution
from . import review
from .findings import severity_rank

# Rule ids that mean the same condition regardless of which tool reported them.
# httpx's -tls-grab and nmap's ssl-cert deliberately share these ids (Phase 6),
# so they collapse into one canonical issue per surface instead of two.
_SHARED_RULES = {
    "tls-cert-expired",
    "tls-cert-expiring-soon",
    "tls-self-signed",
    "tls-hostname-mismatch",
    "tls-deprecated-protocol",
}


def canonical_issue_type(source_tool: str, rule_id: str) -> str:
    """Map a detector to its canonical equivalence-class key. Shared rules are
    tool-independent (``tls:<rule>``); everything else is tool-qualified so
    unrelated detectors are never merged."""
    if rule_id in _SHARED_RULES:
        return f"tls:{rule_id}"
    return f"{source_tool}:{rule_id}"


def _category(issue_type: str) -> str:
    return issue_type.split(":", 1)[0]


def _higher(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def derive_issues(db: Session, execution: ScanExecution) -> dict:
    """Project this execution's findings into canonical Issues/Occurrences.

    Idempotent per execution: re-running upserts the same rows (keyed on the
    unique constraints) rather than duplicating them.
    """
    sightings = {
        s.finding_id: s
        for s in db.execute(
            select(FindingSighting).where(FindingSighting.execution_id == execution.id)
        ).scalars()
    }
    if not sightings:
        return {"issues": 0, "occurrences": 0}

    findings = {
        f.id: f
        for f in db.execute(
            select(Finding).where(Finding.id.in_(list(sightings) or ["__none__"]))
        ).scalars()
    }

    n_issues = n_occ = 0
    for fid, sighting in sightings.items():
        f = findings.get(fid)
        if f is None:
            continue
        itype = canonical_issue_type(f.source_tool, f.rule_id)
        issue = db.execute(
            select(Issue).where(Issue.target_id == f.target_id, Issue.issue_type == itype)
        ).scalar_one_or_none()
        if issue is None:
            issue = Issue(
                target_id=f.target_id, issue_type=itype, category=_category(itype),
                title=f.name or itype, severity=f.severity, status="OBSERVED",
                first_seen_at=f.first_seen_at, last_seen_at=f.last_seen_at,
            )
            db.add(issue)
            db.flush()
            n_issues += 1
        else:
            issue.severity = _higher(issue.severity, f.severity)
            if f.last_seen_at and (issue.last_seen_at is None or f.last_seen_at > issue.last_seen_at):
                issue.last_seen_at = f.last_seen_at
            if f.first_seen_at and (issue.first_seen_at is None or f.first_seen_at < issue.first_seen_at):
                issue.first_seen_at = f.first_seen_at
            if not issue.title:
                issue.title = f.name or itype
            if f.status == "OBSERVED":
                issue.status = "OBSERVED"

        existing = db.execute(
            select(Occurrence).where(
                Occurrence.issue_id == issue.id,
                Occurrence.execution_id == execution.id,
                Occurrence.finding_id == f.id,
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(Occurrence(
                issue_id=issue.id, execution_id=execution.id, finding_id=f.id,
                asset_value=f.asset_value, port=f.port, severity=sighting.severity,
                seen_at=sighting.seen_at,
            ))
            n_occ += 1
            # A genuinely new observation of a previously-verified issue reopens
            # it (§12.3.6). Keyed on a newly-created occurrence, so re-projecting
            # history via backfill (where the occurrence already exists) never
            # spuriously reopens.
            if f.status == "OBSERVED":
                review.maybe_reopen(db, issue)
        else:
            existing.severity = sighting.severity

    return {"issues": n_issues, "occurrences": n_occ}


def backfill_all(db: Session) -> dict:
    """Rebuild the canonical projection from every existing execution, oldest
    first. Idempotent and lossless — safe to run repeatedly; it only reads
    Finding/FindingSighting and upserts Issue/Occurrence."""
    execs = db.execute(
        select(ScanExecution).order_by(ScanExecution.created_at)
    ).scalars().all()
    totals = {"issues": 0, "occurrences": 0, "executions": 0}
    for ex in execs:
        res = derive_issues(db, ex)
        totals["issues"] += res["issues"]
        totals["occurrences"] += res["occurrences"]
        totals["executions"] += 1
    return totals
