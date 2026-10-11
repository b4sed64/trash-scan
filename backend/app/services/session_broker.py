"""Session domain + broker on fakes (PRD v2 §22.4, Phase 18).

Models product sessions with their own opaque identity, verification/quarantine,
and single-writer controller leases. Fake-only — sessions are disabled against
real targets; there is no real listener yet (Phase 19). The safety invariants:

  * a native framework session ID is never a durable authorization identity
    (it may be reused after a restart); association needs attempt correlation +
    transport identity + reviewed fixture proof;
  * unverified or ambiguous sessions accept no operator input;
  * an unexpected second session for an attempt/target is QUARANTINED, never
    silently adopted;
  * one writer across tabs/operators via a fenced lease; an administrator
    takeover revokes the old lease so a stale writer can never act.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models import ControllerLease, LabSession

# Session states (§22.4).
PENDING = "PENDING"
ESTABLISHED_UNVERIFIED = "ESTABLISHED_UNVERIFIED"
READY = "READY"
CONTROLLED = "CONTROLLED"
STOPPING = "STOPPING"
CLOSED = "CLOSED"
LOST = "LOST"
QUARANTINED = "QUARANTINED"

_INPUT_OK_STATES = {READY, CONTROLLED}
_LIVE_STATES = {PENDING, ESTABLISHED_UNVERIFIED, READY, CONTROLLED, STOPPING}

# Initial lease policy (§22.3): 15s lease, 5s heartbeats.
LEASE_SECONDS = 15


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(v: dt.datetime | None) -> dt.datetime | None:
    # SQLite drops tzinfo on reload; coerce naive timestamps to UTC for comparison.
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)


class SessionError(RuntimeError):
    pass


def establish(db: DbSession, *, attempt_id: str, grant_id: str | None, fixture_id: str,
              target_id: str, framework_epoch: str, native_session_id: str,
              transport: str, observed_connection: str, owner_id: str | None,
              lifetime_seconds: int = 600) -> LabSession:
    """Create a product session in ESTABLISHED_UNVERIFIED. If another live
    session already exists for this attempt, the new one is QUARANTINED (an
    unexpected second session is never silently adopted)."""
    existing = db.execute(
        select(LabSession).where(LabSession.attempt_id == attempt_id,
                                 LabSession.state.in_(_LIVE_STATES))
    ).scalars().all()
    sess = LabSession(attempt_id=attempt_id, grant_id=grant_id, fixture_id=fixture_id,
                      target_id=target_id, framework_epoch=framework_epoch,
                      native_session_id=native_session_id, transport=transport,
                      observed_connection=observed_connection, owner_id=owner_id,
                      state=ESTABLISHED_UNVERIFIED, created_at=_now(),
                      expires_at=_now() + dt.timedelta(seconds=lifetime_seconds))
    if existing:
        sess.state = QUARANTINED
        sess.quarantine_reason = "unexpected additional session for this attempt"
    db.add(sess)
    db.flush()
    return sess


def verify(db: DbSession, session: LabSession, *, fixture_association_ok: bool) -> str:
    """Promote ESTABLISHED_UNVERIFIED -> READY only with reviewed fixture
    association; otherwise QUARANTINE. READY does not imply the original
    vulnerability claim is demonstrated."""
    if session.state != ESTABLISHED_UNVERIFIED:
        return session.state
    if fixture_association_ok:
        session.state = READY
    else:
        session.state = QUARANTINED
        session.quarantine_reason = "fixture association could not be verified"
    return session.state


def accepts_input(session: LabSession, *, lease: ControllerLease | None, token: str) -> bool:
    """Input is accepted only for a verified session held by a valid lease.
    Unverified/quarantined sessions and observers (no/invalid lease) cannot
    write."""
    if session.state not in _INPUT_OK_STATES:
        return False
    return lease is not None and lease.active and lease.fencing_token == token \
        and not _lease_expired(lease)


def _lease_expired(lease: ControllerLease) -> bool:
    exp = _aware(lease.expires_at)
    return bool(exp and _now() > exp)


def _active_lease(db: DbSession, session_id: str) -> ControllerLease | None:
    return db.execute(
        select(ControllerLease).where(ControllerLease.session_id == session_id,
                                      ControllerLease.active.is_(True))
    ).scalars().first()


def acquire_lease(db: DbSession, session: LabSession, holder: str, *,
                  takeover: bool = False) -> ControllerLease:
    """Acquire the single-writer lease. A different holder is refused unless
    ``takeover`` (administrator) — which revokes the old lease and issues a new
    fencing token so the previous writer is fenced out."""
    current = _active_lease(db, session.id)
    if current is not None and not _lease_expired(current):
        if current.holder == holder:
            current.expires_at = _now() + dt.timedelta(seconds=LEASE_SECONDS)
            current.heartbeat_at = _now()
            return current
        if not takeover:
            raise SessionError(f"session is controlled by another operator ({current.holder})")
        current.active = False  # fence the old writer
    elif current is not None:
        current.active = False
    lease = ControllerLease(session_id=session.id, holder=holder, fencing_token=str(uuid.uuid4()),
                            active=True, expires_at=_now() + dt.timedelta(seconds=LEASE_SECONDS),
                            heartbeat_at=_now())
    db.add(lease)
    if session.state == READY:
        session.state = CONTROLLED
    db.flush()
    return lease


def heartbeat(db: DbSession, lease: ControllerLease, token: str) -> None:
    if not lease.active or lease.fencing_token != token:
        raise SessionError("stale or invalid lease")
    lease.expires_at = _now() + dt.timedelta(seconds=LEASE_SECONDS)
    lease.heartbeat_at = _now()


def release_lease(db: DbSession, session: LabSession) -> None:
    current = _active_lease(db, session.id)
    if current is not None:
        current.active = False
    if session.state == CONTROLLED:
        session.state = READY


def disconnect(db: DbSession, session: LabSession) -> None:
    """On controller disconnect, stop accepting input immediately by releasing
    the lease. Reconnection requires fresh authentication + lease validation and
    never reruns work or extends lifetime."""
    release_lease(db, session)


def quarantine(db: DbSession, session: LabSession, reason: str) -> None:
    session.state = QUARANTINED
    session.quarantine_reason = reason[:256]
    release_lease(db, session)
