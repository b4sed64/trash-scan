"""Audit-log filtering and ordering."""
from __future__ import annotations

import pytest

ADMIN_PW = "admin-password-123"


def _csrf(c):
    return c.cookies.get("trashscan_csrf")


def _p(c, url, body=None):
    return c.post(url, json=body, headers={"X-CSRF-Token": _csrf(c)})


@pytest.fixture
def admin(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    _p(client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    _p(client, "/api/targets", {"value": "10.10.5.20"})
    _p(client, "/api/targets", {"value": "10.10.6.30"})
    return client


def test_actions_endpoint_lists_distinct(admin):
    actions = admin.get("/api/audit/actions").json()
    assert "TARGET_CREATED" in actions
    assert "PRIVATE_SCOPE_ADDED" in actions
    assert actions == sorted(actions)


def test_filter_by_action(admin):
    only = admin.get("/api/audit/events?action=TARGET_CREATED").json()
    assert only and all(e["action"] == "TARGET_CREATED" for e in only)

    multi = admin.get("/api/audit/events?action=TARGET_CREATED&action=AUTH_SUCCESS").json()
    assert {e["action"] for e in multi} == {"TARGET_CREATED", "AUTH_SUCCESS"}


def test_order_asc_desc(admin):
    asc = [e["seq"] for e in admin.get("/api/audit/events?order=asc").json()]
    desc = [e["seq"] for e in admin.get("/api/audit/events?order=desc").json()]
    assert asc == sorted(asc)
    assert desc == sorted(desc, reverse=True)
    assert asc[0] == 1


def test_free_text_matches_object_id_and_payload(admin):
    targets = admin.get("/api/targets").json()
    tid = targets[0]["id"]
    by_id = admin.get(f"/api/audit/events?q={tid}").json()
    assert by_id and all(e["object_id"] == tid or tid in str(e["payload"]) for e in by_id)

    by_value = admin.get("/api/audit/events?q=10.10.5.20").json()
    assert any(e["action"] == "TARGET_CREATED" for e in by_value)

    by_seq = admin.get("/api/audit/events?q=1").json()
    assert any(e["seq"] == 1 for e in by_seq)
