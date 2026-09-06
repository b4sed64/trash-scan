"""HTTP-level report authorization and audit (RPT-04)."""
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
    sc = _p(client, "/api/admin/accounts",
            {"username": "scan1", "password": SCAN_PW, "role": "SCANNER"}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    t_assigned = _p(client, "/api/targets", {"value": "10.10.5.20"}).json()
    t_other = _p(client, "/api/targets", {"value": "10.10.6.30"}).json()
    _p(client, f"/api/targets/{t_assigned['id']}/assignments", {"user_id": sc["id"]})
    return {"admin": client, "assigned": t_assigned["id"], "other": t_other["id"]}


def test_report_download_is_authorized_and_audited(env):
    admin = env["admin"]
    r = _p(admin, f"/api/targets/{env['assigned']}/reports", {"format": "CSV_ZIP"})
    assert r.status_code == 201
    report_id = r.json()["id"]

    dl = admin.get(f"/api/reports/{report_id}/download", headers={"X-CSRF-Token": _csrf(admin)})
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/zip"

    events = admin.get("/api/audit/events?limit=200").json()
    actions = [e["action"] for e in events]
    assert "REPORT_GENERATED" in actions and "REPORT_EXPORTED" in actions

    # a scanner cannot download a report for a target they are not assigned to
    with TestClient(create_app()) as sc:
        sc.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        assert sc.get(f"/api/reports/{report_id}/download",
                      headers={"X-CSRF-Token": sc.cookies.get("trashscan_csrf")}).status_code == 200
        other = _p(admin, f"/api/targets/{env['other']}/reports", {"format": "CSV_ZIP"}).json()
        assert sc.get(f"/api/reports/{other['id']}/download",
                      headers={"X-CSRF-Token": sc.cookies.get("trashscan_csrf")}).status_code == 404


def test_maintenance_proposal_flow(env):
    admin = env["admin"]
    view = admin.get("/api/admin/maintenance").json()
    assert "tool_versions" in view["current"]
    assert view["current"]["template_set_ok"] is True

    p = _p(admin, "/api/admin/maintenance/proposals", {"note": "bump nuclei to 3.3.8"})
    assert p.status_code == 201
    pid = p.json()["id"]
    approved = _p(admin, f"/api/admin/maintenance/proposals/{pid}/approve", {"decision_note": "ok"})
    assert approved.status_code == 200
    assert approved.json()["state"] == "APPROVED"
    assert "operator_action" in approved.json()

    actions = [e["action"] for e in admin.get("/api/audit/events?limit=200").json()]
    assert "MAINTENANCE_PROPOSED" in actions and "MAINTENANCE_APPROVED" in actions


def test_scanner_cannot_reach_maintenance(env):
    with TestClient(create_app()) as sc:
        sc.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        assert sc.get("/api/admin/maintenance").status_code == 403
