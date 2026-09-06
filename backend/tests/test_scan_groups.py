"""A scan is one unit across many targets; approval, start and stop act on the group."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.constants import ACTIVE_SCAN_ATTESTATION
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
    a = _p(client, "/api/targets", {"value": "10.10.5.20"}).json()
    b = _p(client, "/api/targets", {"value": "10.10.5.21"}).json()
    for t in (a, b):
        _p(client, f"/api/targets/{t['id']}/assignments", {"user_id": sc["id"]})
    return {"admin": client, "t1": a["id"], "t2": b["id"], "scanner_id": sc["id"]}


def _scanner():
    c = TestClient(create_app())
    c.__enter__()
    c.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
    return c


def test_multi_target_passive_is_one_scan(env):
    r = _p(env["admin"], "/api/scans",
           {"target_ids": [env["t1"], env["t2"]], "profile": "PASSIVE"})
    assert r.status_code == 201
    scan_id = r.json()["scan_id"]
    assert len({e["scan_id"] for e in r.json()["executions"]}) == 1

    listing = env["admin"].get("/api/scans").json()
    row = next(g for g in listing if g["scan_id"] == scan_id)
    assert row["target_count"] == 2

    detail = env["admin"].get(f"/api/scans/{scan_id}").json()
    assert len(detail["hosts"]) == 2
    assert {h["target"]["value"] for h in detail["hosts"]} == {"10.10.5.20", "10.10.5.21"}
    assert "severity_counts" in detail["summary"]


def test_active_multi_target_one_approval_then_start(env):
    sc = _scanner()
    try:
        r = _p(sc, "/api/scans", {
            "target_ids": [env["t1"], env["t2"]], "profile": "SAFE_ACTIVE",
            "attestation_text": ACTIVE_SCAN_ATTESTATION,
        })
        assert r.status_code == 201
        scan_id = r.json()["scan_id"]

        queue = env["admin"].get("/api/approvals?include_decided=false").json()
        assert len(queue) == 1 and queue[0]["target_count"] == 2

        # cannot start before approval
        assert _p(sc, f"/api/scans/{scan_id}/start").status_code == 409

        _p(env["admin"], f"/api/approvals/{queue[0]['id']}/approve")
        assert env["admin"].get(f"/api/scans/{scan_id}").json()["state"] == "APPROVED"

        assert _p(sc, f"/api/scans/{scan_id}/start").status_code == 200
        assert env["admin"].get(f"/api/scans/{scan_id}").json()["state"] in (
            "RUNNING", "QUEUED", "COMPLETED", "PARTIAL"
        )
    finally:
        sc.__exit__(None, None, None)


def test_stop_cancels_the_whole_group(env):
    # an active scan waits in AWAITING_APPROVAL; stopping it cancels every execution
    r = _p(env["admin"], "/api/scans", {
        "target_ids": [env["t1"], env["t2"]], "profile": "SAFE_ACTIVE",
        "attestation_text": ACTIVE_SCAN_ATTESTATION,
    })
    scan_id = r.json()["scan_id"]
    assert _p(env["admin"], f"/api/scans/{scan_id}/stop", {"reason": "drill"}).status_code == 200
    detail = env["admin"].get(f"/api/scans/{scan_id}").json()
    assert detail["state"] == "CANCELLED"
    assert all(h["state"] == "CANCELLED" for h in detail["hosts"])
    # stopping again is a conflict — already finished
    assert _p(env["admin"], f"/api/scans/{scan_id}/stop", {"reason": "again"}).status_code == 409


def test_scanner_cannot_start_another_users_scan(env):
    r = _p(env["admin"], "/api/scans", {
        "target_id": env["t1"], "profile": "SAFE_ACTIVE",
        "attestation_text": ACTIVE_SCAN_ATTESTATION,
    })
    scan_id = r.json()["scan_id"]
    approval = env["admin"].get("/api/approvals?include_decided=false").json()[0]
    _p(env["admin"], f"/api/approvals/{approval['id']}/approve")

    sc = _scanner()
    try:
        assert sc.post(f"/api/scans/{scan_id}/start",
                       headers={"X-CSRF-Token": _csrf(sc)}).status_code in (403, 404)
    finally:
        sc.__exit__(None, None, None)
