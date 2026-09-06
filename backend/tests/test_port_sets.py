"""Administrator-defined port sets (reusable named port selections)."""
from __future__ import annotations

import pytest

ADMIN_PW = "admin-password-123"
SCAN_PW = "scanner-password-123"


def _csrf(c):
    return c.cookies.get("trashscan_csrf")


def _p(c, url, body=None):
    return c.post(url, json=body, headers={"X-CSRF-Token": _csrf(c)})


@pytest.fixture
def admin(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    return client


def test_create_list_delete_port_set(admin):
    r = _p(admin, "/api/admin/port-sets",
           {"name": "Databases", "spec": " 1433, 3306 , 5432-5433 ", "note": "db ports"})
    assert r.status_code == 201
    assert r.json()["spec"] == "1433,3306,5432-5433"  # canonicalised

    listing = admin.get("/api/admin/port-sets").json()
    assert [p["name"] for p in listing] == ["Databases"]

    # exposed to the scan page alongside the built-in presets
    presets = admin.get("/api/scans/port-presets").json()
    assert "WEB" in presets["presets"]
    assert any(ps["name"] == "Databases" for ps in presets["port_sets"])

    pid = listing[0]["id"]
    assert admin.delete(f"/api/admin/port-sets/{pid}",
                        headers={"X-CSRF-Token": _csrf(admin)}).status_code == 200
    assert admin.get("/api/admin/port-sets").json() == []


def test_invalid_spec_rejected(admin):
    assert _p(admin, "/api/admin/port-sets",
              {"name": "Bad", "spec": "22,not-a-port"}).status_code == 422


def test_duplicate_name_conflict(admin):
    _p(admin, "/api/admin/port-sets", {"name": "Web", "spec": "80,443"})
    assert _p(admin, "/api/admin/port-sets", {"name": "Web", "spec": "8080"}).status_code == 409


def test_scanner_cannot_manage_port_sets(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    sc = _p(client, "/api/admin/accounts",
            {"username": "scan1", "password": SCAN_PW, "role": "SCANNER"}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as s:
        s.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        assert s.get("/api/admin/port-sets").status_code == 403
        # but the scanner can still see them for the scan form
        assert s.get("/api/scans/port-presets").status_code == 200
