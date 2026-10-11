"""Internal listener + verified session establishment — fake listener (PRD v2 §22.3, Phase 19).

Fake-only: no socket is ever bound and no real callback is received. The safety
core is ``validate_listener_boundary`` — a listener may bind only to a concrete
address inside the declared isolated lab boundary, never a wildcard, loopback,
host, or public/routable interface, and callbacks are accepted only from the
expected fixture source. A callback that does not match the expected fixture
association yields a QUARANTINED session that accepts no input (via the Phase 18
broker). Everything here is additionally behind ``enable_guided_sessions`` (off)
and withheld until the Phase 15 lab isolation gate passes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy.orm import Session as DbSession

from ..models import LabFixture, LabSession, ProofAttempt, SessionGrant
from . import session_broker as broker

# Interfaces a listener may never bind to (wildcards / loopback / host bridge).
_FORBIDDEN_INTERFACES = {"0.0.0.0", "::", "127.0.0.1", "::1", "localhost",
                         "host.docker.internal"}


class ListenerError(RuntimeError):
    pass


def validate_listener_boundary(interface: str, port, allowed_cidrs: list[str]) -> tuple[bool, str]:
    """A listener must bind to a concrete private address inside the declared lab
    boundary. Reject wildcards/loopback/host and any public/routable address."""
    if not interface or interface in _FORBIDDEN_INTERFACES:
        return False, "listener must bind a concrete internal interface, not a wildcard/host/loopback"
    try:
        addr = ipaddress.ip_address(interface)
    except ValueError:
        return False, "listener interface must be a concrete IP inside the lab boundary"
    if addr.is_global or not addr.is_private:
        return False, "listener must not bind to a public/non-private interface"
    if not allowed_cidrs or not any(
            addr in ipaddress.ip_network(c, strict=False) for c in allowed_cidrs):
        return False, "listener interface is outside the declared lab boundary"
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False, "invalid listener port"
    if not (1 <= p <= 65535):
        return False, "listener port out of range"
    return True, "ok"


@dataclass(frozen=True)
class CallbackEvent:
    source_ip: str
    native_session_id: str
    epoch: str


class FakeListener:
    """Simulated internal listener. It binds nothing; ``simulate_callback`` just
    fabricates an inbound-connection event for tests/development."""

    def __init__(self, interface: str, port: int):
        self.interface = interface
        self.port = port
        self.open = True

    def simulate_callback(self, source_ip: str, native_session_id: str, epoch: str) -> CallbackEvent:
        if not self.open:
            raise ListenerError("listener is closed")
        return CallbackEvent(source_ip=source_ip, native_session_id=native_session_id, epoch=epoch)

    def close(self) -> None:
        self.open = False


def establish(db: DbSession, *, attempt: ProofAttempt, grant: SessionGrant, fixture: LabFixture,
              expected_source_ip: str, allowed_cidrs: list[str], callback: CallbackEvent,
              owner_id: str | None, enabled: bool) -> LabSession:
    """Establish a verified session from a (fake) callback. Validates the listener
    boundary, binds via the broker (which quarantines an unexpected second
    session), and verifies fixture association from the callback source. A session
    reaching READY does not by itself prove any claimed impact."""
    if not enabled:
        raise ListenerError("guided sessions are disabled (enable_guided_sessions=false)")
    ok, reason = validate_listener_boundary(grant.listener_interface, grant.listener_port,
                                            allowed_cidrs)
    if not ok:
        raise ListenerError(f"listener boundary rejected: {reason}")
    sess = broker.establish(
        db, attempt_id=attempt.id, grant_id=grant.id, fixture_id=fixture.id,
        target_id=fixture.target_id, framework_epoch=callback.epoch,
        native_session_id=callback.native_session_id, transport=grant.transport,
        observed_connection=f"{callback.source_ip}:{grant.listener_port}", owner_id=owner_id,
        lifetime_seconds=grant.lifetime_seconds,
    )
    if sess.state == broker.QUARANTINED:
        return sess  # unexpected additional session — never adopted
    # Fixture association: the callback must originate from the expected fixture.
    broker.verify(db, sess, fixture_association_ok=(callback.source_ip == expected_source_ip))
    if sess.state == broker.READY:
        attempt.state = "SESSION_ACTIVE"
    db.flush()
    return sess


def terminate(db: DbSession, listener: FakeListener, session: LabSession) -> None:
    """Stop removes BOTH the listener and the session. The parent attempt may
    only complete once no session remains live."""
    session.state = broker.STOPPING
    broker.release_lease(db, session)
    listener.close()
    session.state = broker.CLOSED


def attempt_has_live_session(db: DbSession, attempt_id: str) -> bool:
    from sqlalchemy import select
    live = db.execute(
        select(LabSession).where(
            LabSession.attempt_id == attempt_id,
            LabSession.state.in_((broker.ESTABLISHED_UNVERIFIED, broker.READY,
                                  broker.CONTROLLED, broker.STOPPING)))
    ).scalars().first()
    return live is not None
