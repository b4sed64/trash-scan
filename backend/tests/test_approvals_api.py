"""HTTP-level active-scan approval workflow (PRD §8.1, §24)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.constants import ACTIVE_SCAN_ATTESTATION
from app.main import create_app

ADMIN_PW = "admin-password-123"
SCANNER_PW = "scanner-password-123"


def _csrf(c):
    return c.cookies.get("trashscan_csrf")


def _p(c, url, body=None):
    return c.post(url, json=body, headers={"X-CSRF-Token": _csrf(c)})


@pytest.fixture
def setup(client):
    assert client.post("/api/auth/setup",
                       json={"username": "admin", "password": ADMIN_PW}).status_code == 201
    r = _p(client, "/api/admin/private-cidrs", {"cidr": "10.10.0.0/16"})
    assert r.status_code == 201, r.text
    r = _p(client, "/api/admin/accounts",
           {"username": "scan1", "password": SCANNER_PW, "role": "SCANNER"})
    assert r.status_code == 201, r.text
    sc = r.json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    t = _p(client, "/api/targets", {"value": "10.10.5.20"}).json()
    _p(client, f"/api/targets/{t['id']}/assignments", {"user_id": sc["id"]})
    return {"admin": client, "target": t["id"], "scanner_id": sc["id"]}


def _scanner_client():
    c = TestClient(create_app())
    c.__enter__()
    c.post("/api/auth/login", json={"username": "scan1", "password": SCANNER_PW})
    return c


def test_active_scan_requires_exact_attestation_and_approval(setup):
    admin = setup["admin"]
    sc = _scanner_client()
    try:
        # wrong attestation -> rejected
        bad = _p(sc, f"/api/targets/{setup['target']}/scans",
                 {"profile": "SAFE_ACTIVE", "attestation_text": "I promise"})
        assert bad.status_code == 422

        good = _p(sc, f"/api/targets/{setup['target']}/scans",
                  {"profile": "SAFE_ACTIVE", "attestation_text": ACTIVE_SCAN_ATTESTATION})
        assert good.status_code == 201
        assert good.json()["state"] == "AWAITING_APPROVAL"

        # scanner cannot approve
        queue = admin.get("/api/approvals").json()
        assert len(queue) == 1
        approval_id = queue[0]["id"]
        assert sc.post(f"/api/approvals/{approval_id}/approve",
                       headers={"X-CSRF-Token": _csrf(sc)}).status_code == 403

        # admin approves -> execution runs to a terminal state (eager Celery, fake tools)
        assert _p(admin, f"/api/approvals/{approval_id}/approve").status_code == 200
        detail = admin.get(f"/api/approvals/{approval_id}").json()
        assert detail["state"] == "APPROVED"
        ex_state = admin.get(f"/api/scans/{detail['execution_id']}").json()["state"]
        assert ex_state in ("COMPLETED", "RUNNING", "QUEUED")

        # replay: approving the same approval again is a conflict
        assert _p(admin, f"/api/approvals/{approval_id}/approve").status_code == 409
    finally:
        sc.__exit__(None, None, None)


def test_emergency_stop_endpoint(setup):
    admin = setup["admin"]
    r = _p(admin, "/api/emergency-stop", {"scope": "ALL", "note": "drill"})
    assert r.status_code == 201
    status = admin.get("/api/emergency-stop").json()
    assert status["active"] is not None
    # cannot stack a second active stop
    assert _p(admin, "/api/emergency-stop", {"scope": "ALL"}).status_code == 409
    stop_id = status["active"]["id"]
    assert _p(admin, f"/api/emergency-stop/{stop_id}/clear").status_code == 200
