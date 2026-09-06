"""POST /api/scans — choose a defined target or type a host / IP / CIDR."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

ADMIN_PW = "admin-password-123"
SCAN_PW = "scanner-password-123"


def _csrf(c):
    return c.cookies.get("trashscan_csrf")


def _p(c, url, body=None):
    return c.post(url, json=body, headers={"X-CSRF-Token": _csrf(c)})


@pytest.fixture
def env(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    _p(client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    _p(client, "/api/admin/deny-rules", {"rule_type": "IP", "value": "10.10.9.9", "category": "CUSTOM"})
    sc = _p(client, "/api/admin/accounts",
            {"username": "scan1", "password": SCAN_PW, "role": "SCANNER"}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    t = _p(client, "/api/targets", {"value": "10.10.5.20"}).json()
    _p(client, f"/api/targets/{t['id']}/assignments", {"user_id": sc["id"]})
    return {"admin": client, "assigned": t["id"], "scanner_id": sc["id"]}


def test_scan_by_target_id(env):
    r = _p(env["admin"], "/api/scans", {"target_id": env["assigned"], "profile": "PASSIVE"})
    assert r.status_code == 201
    assert r.json()["target_id"] == env["assigned"]


def test_scan_by_typed_value_reuses_existing_target(env):
    r = _p(env["admin"], "/api/scans", {"target_value": "10.10.5.20", "profile": "PASSIVE"})
    assert r.status_code == 201
    assert r.json()["target_id"] == env["assigned"]
    # no duplicate target created
    assert len(env["admin"].get("/api/targets").json()) == 1


def test_admin_can_scan_a_new_typed_host(env):
    before = len(env["admin"].get("/api/targets").json())
    r = _p(env["admin"], "/api/scans", {"target_value": "10.10.7.7", "profile": "PASSIVE"})
    assert r.status_code == 201
    assert len(env["admin"].get("/api/targets").json()) == before + 1


def test_typed_value_hitting_a_deny_rule_is_rejected(env):
    r = _p(env["admin"], "/api/scans", {"target_value": "10.10.9.9", "profile": "PASSIVE"})
    assert r.status_code == 422
    assert "policy" in r.json()["detail"]


def test_missing_target_is_a_422(env):
    assert _p(env["admin"], "/api/scans", {"profile": "PASSIVE"}).status_code == 422


def test_scanner_cannot_scan_an_undefined_host(env):
    with TestClient(create_app()) as sc:
        sc.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        # their assigned target by value: fine
        ok = sc.post("/api/scans", json={"target_value": "10.10.5.20", "profile": "PASSIVE"},
                     headers={"X-CSRF-Token": sc.cookies.get("trashscan_csrf")})
        assert ok.status_code == 201
        # an undefined host: refused
        bad = sc.post("/api/scans", json={"target_value": "10.10.8.8", "profile": "PASSIVE"},
                      headers={"X-CSRF-Token": sc.cookies.get("trashscan_csrf")})
        assert bad.status_code == 403
        # an unassigned but defined target: also 403
        env["admin"].post("/api/targets", json={"value": "10.10.6.30"},
                          headers={"X-CSRF-Token": _csrf(env["admin"])})
        bad2 = sc.post("/api/scans", json={"target_value": "10.10.6.30", "profile": "PASSIVE"},
                       headers={"X-CSRF-Token": sc.cookies.get("trashscan_csrf")})
        assert bad2.status_code in (403, 404)
