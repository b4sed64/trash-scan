"""Guided session actions — predefined, fake-backed (PRD v2 §22.5, Phase 20).

Guided actions are a small, fixed, reviewed set — inspect execution identity,
basic OS context, verify a seeded marker, capture an observation, terminate.
There is **no free-form input**: each action has a versioned ID, a typed
parameter schema and a fixed implementation. Guided input is never built by
substituting untrusted strings into a shell command, and arbitrary framework
session commands behind a button are prohibited (free-form input lives only in
the separately-gated Phase 22 terminal).

Dispatch is guarded immediately before it happens — verified session, valid
controller lease, action named in the grant, typed params, and a per-session
invocation budget. A client ``request_id`` makes duplicate submits idempotent; a
simulated post-dispatch timeout yields OUTCOME_UNKNOWN and is never auto-resent.
Fake-backed and behind ``enable_guided_sessions`` (off).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models import InteractionRecord, LabSession, SessionGrant
from . import session_broker as broker
from . import stream
from .stream import sanitize_output

# Max guided invocations per session (§22.3 initial default).
TOTAL_INVOCATION_LIMIT = 20
_COUNTED_STATES = ("DISPATCHED", "COMPLETED", "OUTCOME_UNKNOWN")


class DispatchTimeout(Exception):
    """A simulated post-dispatch timeout — the remote outcome is unknown."""


def _marker_impl(session: LabSession, params: dict) -> str:
    return f"marker={params.get('marker', '')}"


# The entire guided action registry. Fixed implementations only.
ACTIONS: dict[str, dict] = {
    "whoami": {"version": "1", "effect": "reads current execution identity",
               "schema": {}, "max_bytes": 16384, "max_seconds": 30,
               "impl": lambda s, p: "uid=1000(lab-fixture-user) gid=1000(lab)"},
    "os-context": {"version": "1", "effect": "basic OS/architecture context",
                   "schema": {}, "max_bytes": 16384, "max_seconds": 30,
                   "impl": lambda s, p: "Linux lab-fixture 5.x x86_64"},
    "read-marker": {"version": "1", "effect": "verify a seeded non-sensitive marker",
                    "schema": {"marker": {"type": "string", "required": True, "max_length": 64}},
                    "max_bytes": 16384, "max_seconds": 30, "impl": _marker_impl},
    "capture-observation": {"version": "1", "effect": "capture a reviewed proof observation",
                            "schema": {"note": {"type": "string", "max_length": 256}},
                            "max_bytes": 16384, "max_seconds": 30,
                            "impl": lambda s, p: f"observation: {p.get('note', '')}"},
    "terminate": {"version": "1", "effect": "terminate the session", "schema": {},
                  "terminates": True, "max_bytes": 256, "max_seconds": 5,
                  "impl": lambda s, p: "session terminated"},
}

_runner_override = None


def set_runner(fn) -> None:
    global _runner_override
    _runner_override = fn


def _run(action: dict, session: LabSession, params: dict) -> str:
    if _runner_override is not None:
        return _runner_override(action, session, params)
    return action["impl"](session, params)


class GuidedError(ValueError):
    pass


def _validate_params(action: dict, params: dict) -> str | None:
    schema = action.get("schema") or {}
    for name, spec in schema.items():
        if spec.get("required") and name not in params:
            return f"missing required parameter: {name}"
        if name in params:
            val = params[name]
            if spec.get("type") == "string" and not isinstance(val, str):
                return f"parameter {name} must be a string"
            ml = spec.get("max_length")
            if ml and isinstance(val, str) and len(val) > ml:
                return f"parameter {name} exceeds max length {ml}"
    for name in params:
        if name not in schema:
            return f"unknown parameter: {name}"
    return None


def _reject(db: DbSession, session_id: str, action_id: str, request_id: str, params: dict,
            reason: str) -> InteractionRecord:
    rec = InteractionRecord(session_id=session_id, action_id=action_id, request_id=request_id,
                            params=params, state="REJECTED", reason=reason[:256])
    db.add(rec)
    db.flush()
    return rec


def dispatch(db: DbSession, *, session: LabSession, grant: SessionGrant, action_id: str,
             params: dict, lease, token: str, request_id: str, enabled: bool) -> InteractionRecord:
    """Dispatch one guided action. Every precondition is checked immediately
    before dispatch; failures produce a REJECTED record rather than acting."""
    if not enabled:
        raise GuidedError("guided sessions are disabled")

    # Idempotency: a duplicate submit returns the existing record, not a new op.
    existing = db.execute(
        select(InteractionRecord).where(InteractionRecord.session_id == session.id,
                                        InteractionRecord.request_id == request_id)
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    action = ACTIONS.get(action_id)
    if action is None:
        return _reject(db, session.id, action_id, request_id, params, "unknown action")
    if action_id not in (grant.guided_action_ids or []):
        return _reject(db, session.id, action_id, request_id, params, "action not in grant")
    if not broker.accepts_input(session, lease=lease, token=token):
        return _reject(db, session.id, action_id, request_id, params,
                       "no valid controller lease or session not ready")
    perr = _validate_params(action, params)
    if perr is not None:
        return _reject(db, session.id, action_id, request_id, params, perr)
    used = db.execute(
        select(InteractionRecord).where(InteractionRecord.session_id == session.id,
                                        InteractionRecord.state.in_(_COUNTED_STATES))
    ).scalars().all()
    if len(used) >= TOTAL_INVOCATION_LIMIT:
        return _reject(db, session.id, action_id, request_id, params, "session action budget exceeded")

    # Persist the intended action BEFORE dispatch, then run the fixed impl.
    rec = InteractionRecord(session_id=session.id, action_id=action_id,
                            action_version=action.get("version", ""), request_id=request_id,
                            params=params, state="DISPATCHED",
                            effect_claim=action.get("effect", "")[:256])
    db.add(rec)
    db.flush()
    try:
        output = _run(action, session, params)
    except DispatchTimeout:
        rec.state = "OUTCOME_UNKNOWN"
        rec.reason = "post-dispatch timeout; remote outcome unknown; not auto-resent"
        stream.append_gap(db, _attempt_of(session), "guided action outcome unknown")
        return rec
    rec.state = "COMPLETED"
    rec.output = sanitize_output(output, action.get("max_bytes", 16384))
    if action.get("terminates"):
        session.state = broker.CLOSED
        broker.release_lease(db, session)
    stream.append_output(db, _attempt_of(session), f"[{action_id}] {rec.output}")
    # A command returning output is its own evidence event — never a proof effect.
    from . import session_evidence
    session_evidence.capture(db, session.id, session_evidence.COMMAND_OUTPUT,
                             actor=request_id, evaluator=f"guided:{action_id}",
                             effect_claim=action.get("effect", "")[:256],
                             limitations="output is evidence for this operation only")
    db.flush()
    return rec


def _attempt_of(session: LabSession) -> str:
    return session.attempt_id
