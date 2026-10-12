"""Administrator target-session terminal — fake channel (PRD v2 §22.5, Phase 22).

The ONLY free-form-input capability, and the most restricted. Fake-backed: input
is echoed back through the admitted session channel as capability-limited
command-output; no real command runs, no PTY/resize/binary is emulated, and it
can never start a module, change framework settings or reach a different target.

The authorization boundary is the grant + controller lease + verified session —
NOT a command blacklist. Everything is administrator-only and behind
``enable_lab_terminal`` (off), with a separate terminal grant/attestation
referencing the exact verified session and a bounded absolute time.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..models import LabSession, TerminalFrameReceipt, TerminalGrant
from . import session_broker as broker
from . import stream

TERMINAL_ATTESTATION = (
    "I am an administrator operating only the admitted lab session channel within "
    "the granted time, and I accept accountability for each command"
)

MAX_FRAME_BYTES = 4096  # §22.5 initial input/paste cap


def capabilities() -> dict:
    """Disclose the ACTUAL interaction capability — a command-output panel, not a
    full terminal. Unsupported features are disclosed, never emulated."""
    return {"mode": "command-output", "pty": False, "resize": False, "binary_streams": False,
            "interactive_programs": False, "max_input_bytes": MAX_FRAME_BYTES,
            "max_paste_bytes": MAX_FRAME_BYTES,
            "note": "A command-output panel that must not masquerade as a full terminal; "
                    "it acts only through the admitted session channel and cannot start "
                    "modules, change settings, or reach another target."}


class TerminalError(ValueError):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)


def grant_terminal(db: DbSession, *, session: LabSession, admin, attestation: str,
                   allowed_seconds: int, enabled: bool) -> TerminalGrant:
    if not enabled:
        raise TerminalError("terminal is disabled (enable_lab_terminal=false)")
    if attestation.strip() != TERMINAL_ATTESTATION:
        raise TerminalError("exact terminal attestation text is required")
    if session.state not in (broker.READY, broker.CONTROLLED):
        raise TerminalError("session is not verified/ready for a terminal grant")
    # One active terminal grant per session; a new grant does not restart clocks.
    for g in db.execute(
            select(TerminalGrant).where(TerminalGrant.session_id == session.id,
                                        TerminalGrant.active.is_(True))).scalars():
        g.active = False
    grant = TerminalGrant(session_id=session.id, admin_id=admin.id, attestation=attestation,
                          active=True, expires_at=_now() + dt.timedelta(seconds=allowed_seconds))
    db.add(grant)
    db.flush()
    return grant


def _next_seq(db: DbSession, session_id: str) -> int:
    cur = db.execute(
        select(func.max(TerminalFrameReceipt.seq)).where(
            TerminalFrameReceipt.session_id == session_id)).scalar()
    return (cur or 0) + 1


def submit_frame(db: DbSession, *, session: LabSession, grant: TerminalGrant | None, lease,
                 token: str, input_text: str, request_id: str, enabled: bool) -> TerminalFrameReceipt:
    """Submit one bounded input frame. Deduplicated by request_id; a rejected
    frame still records a receipt (accountability). Acts only through the fake
    admitted channel."""
    if not enabled:
        raise TerminalError("terminal is disabled")

    existing = db.execute(
        select(TerminalFrameReceipt).where(TerminalFrameReceipt.session_id == session.id,
                                           TerminalFrameReceipt.request_id == request_id)
    ).scalar_one_or_none()
    if existing is not None:
        return existing  # reconnect/duplicate never replays input

    nbytes = len(input_text.encode("utf-8", errors="ignore"))
    reason = None
    if grant is None or not grant.active or grant.session_id != session.id:
        reason = "no active terminal grant for this session"
    elif _aware(grant.expires_at) and _now() > _aware(grant.expires_at):
        reason = "terminal grant expired"
    elif not broker.accepts_input(session, lease=lease, token=token):
        reason = "no valid controller lease or session not ready"
    elif nbytes > MAX_FRAME_BYTES:
        reason = f"input frame exceeds {MAX_FRAME_BYTES} bytes"

    receipt = TerminalFrameReceipt(session_id=session.id,
                                   grant_id=grant.id if grant else None,
                                   seq=_next_seq(db, session.id), request_id=request_id,
                                   input_bytes=nbytes, accepted=reason is None,
                                   reason=(reason or "")[:256])
    db.add(receipt)
    db.flush()
    if reason is None:
        # Act only through the admitted (fake) session channel: a capability-
        # limited echo, explicitly not a real shell.
        out = f"$ {input_text}\n(fake session channel: command-output only; no PTY/exec)"
        stream.append_output(db, session.attempt_id, out)
    return receipt
