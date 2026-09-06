"""AuditService — tamper-evident hash-chained audit trail (PRD section 18).

Each event stores ``curr_hash = SHA-256(prev_hash || canonical_event)`` where the
canonical event is a deterministic JSON serialisation. Events are append-only:
there is no update or delete path exposed anywhere in the application.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..models import AuditEvent

GENESIS_HASH = "0" * 64

# A stable 64-bit key for the Postgres advisory lock that serializes audit
# appends across the API, worker and beat processes (PRD §18 requires a single
# monotonic sequence and a single hash chain).
_AUDIT_LOCK_KEY = 0x7A5C_A0D1_7A5C_A0D1 - (1 << 63)


def _serialize_appends(db: Session) -> None:
    """Take a transaction-scoped lock so concurrent appenders cannot race on
    ``seq`` or fork the hash chain. No-op on SQLite (tests are single-threaded)."""
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})

# Fields that must never appear in an audit payload (PRD 18).
_FORBIDDEN_KEYS = {"password", "password_hash", "session", "session_token", "csrf_token", "secret"}


def _canonical_event(
    seq: int,
    ts: dt.datetime,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    payload: dict,
    prev_hash: str,
) -> bytes:
    body = {
        "seq": seq,
        "ts": ts.astimezone(dt.timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _compute_hash(prev_hash: str, canonical: bytes) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + canonical).hexdigest()


def _scrub(payload: dict | None) -> dict:
    payload = payload or {}
    cleaned = {}
    for key, val in payload.items():
        if key.lower() in _FORBIDDEN_KEYS:
            continue
        cleaned[key] = val
    return cleaned


class AuditService:
    """All methods must be called inside the caller's transaction."""

    @staticmethod
    def append(
        db: Session,
        *,
        actor: str,
        action: str,
        object_type: str = "",
        object_id: str = "",
        payload: dict | None = None,
    ) -> AuditEvent:
        _serialize_appends(db)
        last = db.execute(
            select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)
        ).scalar_one_or_none()
        prev_hash = last.curr_hash if last else GENESIS_HASH
        seq = (last.seq if last else 0) + 1
        ts = dt.datetime.now(dt.timezone.utc)
        clean_payload = _scrub(payload)
        canonical = _canonical_event(
            seq, ts, actor, action, object_type, object_id, clean_payload, prev_hash
        )
        curr_hash = _compute_hash(prev_hash, canonical)
        event = AuditEvent(
            seq=seq,
            ts=ts,
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            payload=clean_payload,
            prev_hash=prev_hash,
            curr_hash=curr_hash,
        )
        db.add(event)
        db.flush()
        return event

    @staticmethod
    def verify_chain(db: Session) -> dict:
        """Recompute the whole chain. Returns a structured result."""
        events = db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all()
        expected_prev = GENESIS_HASH
        for idx, event in enumerate(events, start=1):
            if event.seq != idx:
                return {
                    "ok": False,
                    "checked": idx - 1,
                    "total": len(events),
                    "failed_seq": event.seq,
                    "reason": f"sequence gap: expected {idx}, found {event.seq}",
                }
            if event.prev_hash != expected_prev:
                return {
                    "ok": False,
                    "checked": idx - 1,
                    "total": len(events),
                    "failed_seq": event.seq,
                    "reason": "prev_hash does not match the previous event",
                }
            canonical = _canonical_event(
                event.seq,
                event.ts,
                event.actor,
                event.action,
                event.object_type,
                event.object_id,
                event.payload,
                event.prev_hash,
            )
            recomputed = _compute_hash(event.prev_hash, canonical)
            if recomputed != event.curr_hash:
                return {
                    "ok": False,
                    "checked": idx - 1,
                    "total": len(events),
                    "failed_seq": event.seq,
                    "reason": "curr_hash does not match recomputed hash (payload mutated)",
                }
            expected_prev = event.curr_hash
        return {"ok": True, "checked": len(events), "total": len(events)}
