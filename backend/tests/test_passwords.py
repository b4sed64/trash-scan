"""Self password change and administrator password reset (PRD §5.2, AUTH-04)."""
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
    sc = _p(client, "/api/admin/accounts",
            {"username": "scan1", "password": SCAN_PW, "role": "SCANNER"}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    return {"admin": client, "scanner_id": sc["id"]}


def test_self_change_password_rotates_other_sessions(env):
    admin = env["admin"]

    # a second admin session
    with TestClient(create_app()) as other:
        other.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert other.get("/api/auth/me").status_code == 200

        assert _p(admin, "/api/auth/change-password",
                  {"current_password": "wrong", "new_password": "brand-new-pw-123"}).status_code == 403
        ok = _p(admin, "/api/auth/change-password",
                {"current_password": ADMIN_PW, "new_password": "brand-new-pw-123"})
        assert ok.status_code == 200

        # caller keeps their session, the other session is revoked
        assert admin.get("/api/auth/me").status_code == 200
        assert other.get("/api/auth/me").status_code == 401

    fresh = TestClient(create_app())
    with fresh:
        assert fresh.post("/api/auth/login",
                          json={"username": "admin", "password": ADMIN_PW}).status_code == 401
        assert fresh.post("/api/auth/login",
                          json={"username": "admin", "password": "brand-new-pw-123"}).status_code == 200


def test_admin_reset_forces_target_relogin(env):
    admin = env["admin"]

    with TestClient(create_app()) as scanner:
        scanner.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        assert scanner.get("/api/auth/me").status_code == 200

        r = _p(admin, f"/api/admin/accounts/{env['scanner_id']}/reset-password",
               {"new_password": "reset-by-admin-123"})
        assert r.status_code == 200

        assert scanner.get("/api/auth/me").status_code == 401  # session revoked

    with TestClient(create_app()) as scanner:
        assert scanner.post("/api/auth/login",
                            json={"username": "scan1", "password": SCAN_PW}).status_code == 401
        assert scanner.post("/api/auth/login",
                            json={"username": "scan1", "password": "reset-by-admin-123"}).status_code == 200

    actions = [e["action"] for e in admin.get("/api/audit/events?limit=200").json()]
    assert "PASSWORD_CHANGED" not in actions  # this was a reset, not a self-change
    assert "PASSWORD_RESET" in actions


def test_scanner_cannot_reset_passwords(env):
    with TestClient(create_app()) as scanner:
        scanner.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        r = scanner.post(f"/api/admin/accounts/{env['scanner_id']}/reset-password",
                         json={"new_password": "nope-nope-nope-1"},
                         headers={"X-CSRF-Token": scanner.cookies.get("trashscan_csrf")})
        assert r.status_code == 403
