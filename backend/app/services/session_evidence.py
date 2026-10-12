"""Session evidence + recovery reporting (PRD v2 §22.6, Phase 21).

Keeps the three evidence kinds strictly separate — a session opening, a command
returning output, and a declared proof effect are different claims, and only a
PROOF_EFFECT with its own demonstrated predicate asserts an effect. A session
report distinguishes demonstrated effect, session state, transcript gaps and any
recovery incident so none is mistaken for another.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models import LabSession, RecoveryRecord, SessionEvidence, StreamEvent

SESSION_OPENED = "SESSION_OPENED"
COMMAND_OUTPUT = "COMMAND_OUTPUT"
PROOF_EFFECT = "PROOF_EFFECT"


def capture(db: DbSession, session_id: str, kind: str, *, actor: str = "", evaluator: str = "",
            effect_claim: str = "", limitations: str = "", demonstrated: bool = False,
            seq_start: int | None = None, seq_end: int | None = None) -> SessionEvidence:
    # A non-PROOF_EFFECT kind can never assert demonstrated impact.
    if kind != PROOF_EFFECT:
        demonstrated = False
    ev = SessionEvidence(session_id=session_id, kind=kind, actor=actor, evaluator=evaluator,
                         effect_claim=effect_claim[:256], limitations=limitations[:256],
                         demonstrated=demonstrated, seq_start=seq_start, seq_end=seq_end)
    db.add(ev)
    db.flush()
    return ev


def session_report(db: DbSession, session: LabSession) -> dict:
    """A bounded report that keeps the dimensions separate (§Exit/handoff)."""
    evidence = db.execute(
        select(SessionEvidence).where(SessionEvidence.session_id == session.id)
        .order_by(SessionEvidence.created_at)
    ).scalars().all()
    gaps = db.execute(
        select(StreamEvent).where(StreamEvent.attempt_id == session.attempt_id,
                                  StreamEvent.event_type == "GAP")
    ).scalars().all()
    recovery = db.execute(
        select(RecoveryRecord).where(RecoveryRecord.fixture_id == session.fixture_id)
        .order_by(RecoveryRecord.created_at.desc())
    ).scalars().all()
    demonstrated = any(e.kind == PROOF_EFFECT and e.demonstrated for e in evidence)
    return {
        "session_id": session.id,
        "session_state": session.state,
        "demonstrated_effect": demonstrated,
        "evidence": [{"kind": e.kind, "effect_claim": e.effect_claim,
                      "demonstrated": e.demonstrated, "limitations": e.limitations,
                      "range": [e.seq_start, e.seq_end]} for e in evidence],
        "transcript_gaps": len(gaps),
        "recovery_incidents": [{"outcome": r.outcome, "detail": r.detail} for r in recovery
                               if r.outcome in ("RECOVERY_FAILED", "PENDING")],
    }
