"""Live execution workspace streaming — durable events + sanitization (PRD v2 §22.6, Phase 17).

The streaming contract, built on fake streams (no target traffic). Events are
durable and ordered per attempt with a monotonic ``seq``; status is database
truth and output never overwrites it. Output is sanitized at write time (ANSI
and control sequences stripped, HTML escaped) so an archived or rendered
transcript can never execute code or smuggle escape sequences — the renderer is
display only. The transcript is bounded; overflow produces a visible GAP rather
than silent loss, and reconnect replays strictly after the client's last cursor.
"""
from __future__ import annotations

import datetime as dt
import html
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import ProofAttempt, StreamEvent

# Event types.
STATUS = "STATUS"
OUTPUT = "OUTPUT"
EVIDENCE = "EVIDENCE"
GAP = "GAP"

# §22.6 proposes ~1 MiB text per session; keep per-payload bounded too.
TRANSCRIPT_LIMIT_BYTES = 1024 * 1024
MAX_PAYLOAD = 8192

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_output(text: str, max_len: int = MAX_PAYLOAD) -> str:
    """Strip terminal escape/control sequences and HTML-escape, then bound.
    Synthetic/fixture output is still untrusted and gets the same treatment."""
    t = _ANSI.sub("", text or "")
    t = _CTRL.sub("", t)
    t = html.escape(t)
    return t[:max_len]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _next_seq(db: Session, attempt_id: str) -> int:
    cur = db.execute(
        select(func.max(StreamEvent.seq)).where(StreamEvent.attempt_id == attempt_id)
    ).scalar()
    return (cur or 0) + 1


def _output_bytes(db: Session, attempt_id: str) -> int:
    rows = db.execute(
        select(StreamEvent.payload).where(StreamEvent.attempt_id == attempt_id,
                                          StreamEvent.event_type == OUTPUT)
    ).scalars().all()
    return sum(len(p or "") for p in rows)


def _append(db: Session, attempt_id: str, event_type: str, payload: str) -> StreamEvent:
    ev = StreamEvent(attempt_id=attempt_id, seq=_next_seq(db, attempt_id), event_type=event_type,
                     payload=payload, server_ts=_now())
    db.add(ev)
    db.flush()
    return ev


def append_status(db: Session, attempt_id: str, state: str) -> StreamEvent:
    # Status payload is a short known token; no sanitization of untrusted text.
    return _append(db, attempt_id, STATUS, state[:64])


def append_evidence(db: Session, attempt_id: str, summary: str) -> StreamEvent:
    return _append(db, attempt_id, EVIDENCE, sanitize_output(summary))


def append_output(db: Session, attempt_id: str, text: str) -> StreamEvent:
    """Append sanitized OUTPUT, honouring the transcript bound. When the bound is
    reached, emit a single GAP marking truncation instead of more output."""
    clean = sanitize_output(text)
    if _output_bytes(db, attempt_id) + len(clean) > TRANSCRIPT_LIMIT_BYTES:
        return _append(db, attempt_id, GAP,
                       "transcript limit reached — subsequent output truncated")
    return _append(db, attempt_id, OUTPUT, clean)


def append_gap(db: Session, attempt_id: str, reason: str) -> StreamEvent:
    return _append(db, attempt_id, GAP, sanitize_output(reason, 256))


def events_after(db: Session, attempt_id: str, after_seq: int) -> list[dict]:
    """Replay events strictly after ``after_seq`` (reconnect cursor). If the
    cursor points past the newest event the result is empty; if it predates the
    earliest retained event a GAP is surfaced first."""
    rows = db.execute(
        select(StreamEvent).where(StreamEvent.attempt_id == attempt_id,
                                  StreamEvent.seq > after_seq)
        .order_by(StreamEvent.seq)
    ).scalars().all()
    out: list[dict] = []
    if after_seq > 0 and rows:
        earliest = db.execute(
            select(func.min(StreamEvent.seq)).where(StreamEvent.attempt_id == attempt_id)
        ).scalar()
        if earliest is not None and after_seq + 1 < earliest:
            out.append({"seq": after_seq, "type": GAP, "server_ts": None,
                        "payload": "requested cursor is older than retained output"})
    for e in rows:
        out.append({"seq": e.seq, "type": e.event_type, "server_ts": e.server_ts,
                    "payload": e.payload})
    return out


def transcript(db: Session, attempt_id: str) -> str:
    rows = db.execute(
        select(StreamEvent).where(StreamEvent.attempt_id == attempt_id,
                                  StreamEvent.event_type == OUTPUT)
        .order_by(StreamEvent.seq)
    ).scalars().all()
    return "\n".join(e.payload for e in rows)[:TRANSCRIPT_LIMIT_BYTES]
