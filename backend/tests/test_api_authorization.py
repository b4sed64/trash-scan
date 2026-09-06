"""End-to-end authorization and scope-boundary tests through the HTTP API.

Covers the Phase 1 acceptance criteria: first-run setup, account/assignment
management, an unassigned scanner being blocked at the API, passive discovery on
an assigned target, and deny-rule rejection before any tool launch.
"""
from __future__ import annotations

import pytest

ADMIN_PW = "admin-password-123"
SCANNER_PW = "scanner-password-123"


def _csrf(client):
    return client.cookies.get("trashscan_csrf")


def _post(client, url, json=None):
    return client.post(url, json=json, headers={"X-CSRF-Token": _csrf(client)})


def _patch(client, url, json=None):
    return client.patch(url, json=json, headers={"X-CSRF-Token": _csrf(client)})


def _delete(client, url):
    return client.delete(url, headers={"X-CSRF-Token": _csrf(client)})


@pytest.fixture
def admin_client(client):
    assert client.get("/api/auth/setup-status").json()["needs_setup"] is True
    r = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 201
    return client


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r


def test_setup_runs_once(admin_client):
    r = admin_client.post("/api/auth/setup", json={"username": "second", "password": ADMIN_PW})
    assert r.status_code == 409


def test_scanner_cannot_reach_admin_routes_or_unassigned_target(admin_client):
    # admin creates a private range, a scanner and two targets
    assert _post(admin_client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"}).status_code == 201
    sc = _post(admin_client, "/api/admin/accounts",
               {"username": "scan1", "password": SCANNER_PW, "role": "SCANNER"})
    assert sc.status_code == 201
    scanner_id = sc.json()["id"]
    # disabled by default -> cannot log in yet
    fresh = admin_client
    bad = fresh.post("/api/auth/login", json={"username": "scan1", "password": SCANNER_PW})
    assert bad.status_code == 401
    assert _patch(admin_client, f"/api/admin/accounts/{scanner_id}", {"is_active": True}).status_code == 200

    t1 = _post(admin_client, "/api/targets", {"value": "10.10.5.20"})
    t2 = _post(admin_client, "/api/targets", {"value": "10.10.6.30"})
    assert t1.status_code == 201 and t2.status_code == 201
    t1_id, t2_id = t1.json()["id"], t2.json()["id"]
    assert _post(admin_client, f"/api/targets/{t1_id}/assignments",
                 {"user_id": scanner_id}).status_code == 200

    # now act as the scanner in a separate client
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as sclient:
        _login(sclient, "scan1", SCANNER_PW)
        # sees only the assigned target
        listing = sclient.get("/api/targets").json()
        assert [t["id"] for t in listing] == [t1_id]
        # assigned target is visible
        assert sclient.get(f"/api/targets/{t1_id}").status_code == 200
        # unassigned target is a 404 through the API, not just hidden in the UI
        assert sclient.get(f"/api/targets/{t2_id}").status_code == 404
        # scanner cannot use admin routes
        assert sclient.get("/api/admin/accounts").status_code == 403
        assert sclient.post(
            "/api/targets", json={"value": "10.10.9.9"},
            headers={"X-CSRF-Token": sclient.cookies.get("trashscan_csrf")},
        ).status_code == 403
        # passive discovery works on the assigned target — created idle, then Started
        # (runs inline via eager Celery)
        pr = sclient.post(
            f"/api/targets/{t1_id}/scans",
            json={"profile": "PASSIVE"},
            headers={"X-CSRF-Token": sclient.cookies.get("trashscan_csrf")},
        )
        assert pr.status_code == 201
        assert pr.json()["classification"] == "PASSIVE"
        assert pr.json()["state"] == "DRAFT"
        sclient.post(
            f"/api/scans/{pr.json()['scan_id']}/start",
            headers={"X-CSRF-Token": sclient.cookies.get("trashscan_csrf")},
        )
        target = sclient.get(f"/api/targets/{t1_id}").json()
        assert target["assets"], "expected discovered assets"
        assert all(a["approved"] is False for a in target["assets"]), "discoveries must be unapproved"
        # a scanner cannot queue an active scan through the passive route
        assert sclient.post(
            f"/api/targets/{t1_id}/scans", json={"profile": "SAFE_ACTIVE"},
            headers={"X-CSRF-Token": sclient.cookies.get("trashscan_csrf")},
        ).status_code == 422


def test_csrf_required_for_unsafe_requests(admin_client):
    r = admin_client.post("/api/targets", json={"value": "10.10.1.1"})  # no CSRF header
    assert r.status_code == 403


def test_deny_rule_blocks_target_creation(admin_client):
    _post(admin_client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    assert _post(admin_client, "/api/admin/deny-rules",
                 {"rule_type": "IP", "value": "10.10.5.5", "category": "CUSTOM"}).status_code == 201
    r = _post(admin_client, "/api/targets", {"value": "10.10.5.5"})
    assert r.status_code == 422
    assert "policy" in r.json()["detail"]


def test_admin_can_add_single_label_domain_suffix_deny_rule(admin_client):
    r = _post(admin_client, "/api/admin/deny-rules",
              {"rule_type": "DOMAIN_SUFFIX", "value": ".example", "category": "CUSTOM"})
    assert r.status_code == 201
    assert r.json()["value"] == "example"
    blocked = _post(admin_client, "/api/targets", {"value": "host.example"})
    assert blocked.status_code == 422


def test_builtin_sector_denylist_present(admin_client):
    rules = admin_client.get("/api/admin/deny-rules").json()
    assert any(r["value"] == "mil" and r["is_builtin"] for r in rules)
    # built-in rules cannot be deleted
    mil = next(r for r in rules if r["value"] == "mil")
    assert _delete(admin_client, f"/api/admin/deny-rules/{mil['id']}").status_code == 400


def test_public_target_requires_exact_attestation(admin_client):
    _post(admin_client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    bad = _post(admin_client, "/api/targets",
                {"value": "shop.example.com", "is_public": True,
                 "attestation_checkbox": True, "attestation_text": "yeah I own it"})
    assert bad.status_code == 422
    good = _post(admin_client, "/api/targets",
                 {"value": "shop.example.com", "is_public": True, "attestation_checkbox": True,
                  "attestation_text":
                      "I confirm this team owns or has written authorization to scan this target"})
    assert good.status_code == 201
    assert good.json()["attestation"]["by"] is not None


def test_disabling_account_invalidates_sessions(admin_client):
    _post(admin_client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    sc = _post(admin_client, "/api/admin/accounts",
               {"username": "scan2", "password": SCANNER_PW, "role": "SCANNER"}).json()
    _patch(admin_client, f"/api/admin/accounts/{sc['id']}", {"is_active": True})

    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as sclient:
        _login(sclient, "scan2", SCANNER_PW)
        assert sclient.get("/api/auth/me").status_code == 200
        _patch(admin_client, f"/api/admin/accounts/{sc['id']}", {"is_active": False})
        assert sclient.get("/api/auth/me").status_code == 401


def test_audit_verification_endpoint(admin_client):
    r = _post(admin_client, "/api/audit/verify")
    assert r.status_code == 200
    assert r.json()["ok"] is True
