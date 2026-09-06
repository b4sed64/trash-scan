"""Audit chain canonicalisation and tamper-evidence (PRD 24, 27.1)."""
from __future__ import annotations

from app.models import AuditEvent
from app.services import AuditService


def _seed(db, n=3):
    for i in range(n):
        AuditService.append(
            db, actor="user:test", action="UNIT_TEST",
            object_type="thing", object_id=str(i), payload={"i": i},
        )
    db.commit()


def test_chain_links_and_verifies(db):
    _seed(db)
    events = db.query(AuditEvent).order_by(AuditEvent.seq).all()
    assert [e.seq for e in events] == [1, 2, 3]
    assert events[0].prev_hash == "0" * 64
    assert events[1].prev_hash == events[0].curr_hash
    assert AuditService.verify_chain(db)["ok"] is True


def test_secrets_are_scrubbed(db):
    AuditService.append(
        db, actor="user:test", action="LOGIN",
        payload={"ip": "10.0.0.1", "password": "hunter2", "csrf_token": "abc"},
    )
    db.commit()
    event = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
    assert "password" not in event.payload
    assert "csrf_token" not in event.payload
    assert event.payload["ip"] == "10.0.0.1"


def test_payload_mutation_is_detected(db):
    _seed(db)
    victim = db.query(AuditEvent).filter(AuditEvent.seq == 2).one()
    victim.payload = {"i": 999}
    db.commit()
    result = AuditService.verify_chain(db)
    assert result["ok"] is False
    assert result["failed_seq"] == 2


def test_deleted_event_breaks_chain(db):
    _seed(db, 4)
    db.query(AuditEvent).filter(AuditEvent.seq == 3).delete()
    db.commit()
    result = AuditService.verify_chain(db)
    assert result["ok"] is False
