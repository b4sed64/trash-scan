"""POST /api/scans — choose defined targets and/or type hosts / IPs / CIDRs,
optionally with a custom port selection."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.constants import ACTIVE_SCAN_ATTESTATION
from app.main import create_app
from app.scan_profiles import PortSpecError, parse_port_spec

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
    _p(client, "/api/admin/deny-rules",
       {"rule_type": "IP", "value": "10.10.9.9", "category": "CUSTOM"})
    sc = _p(client, "/api/admin/accounts",
            {"username": "scan1", "password": SCAN_PW, "role": "SCANNER"}).json()
    client.patch(f"/api/admin/accounts/{sc['id']}", json={"is_active": True},
                 headers={"X-CSRF-Token": _csrf(client)})
    t = _p(client, "/api/targets", {"value": "10.10.5.20"}).json()
    _p(client, f"/api/targets/{t['id']}/assignments", {"user_id": sc["id"]})
    return {"admin": client, "assigned": t["id"], "scanner_id": sc["id"]}


# --- port spec validation --------------------------------------------
@pytest.mark.parametrize("spec,expected", [
    ("22,80,443", "22,80,443"),
    ("1-1024", "1-1024"),
    (" 22 , 80 , 8000-8100 ", "22,80,8000-8100"),
    ("", None),
    (None, None),
])
def test_parse_port_spec_ok(spec, expected):
    assert parse_port_spec(spec) == expected


@pytest.mark.parametrize("spec", ["0", "70000", "80-20", "abc", "22,,x", "1-99999"])
def test_parse_port_spec_rejects(spec):
    with pytest.raises(PortSpecError):
        parse_port_spec(spec)


def test_parse_port_spec_caps_total():
    with pytest.raises(PortSpecError):
        parse_port_spec("1-65535")


# --- targeting --------------------------------------------------------
def test_scan_by_target_id(env):
    r = _p(env["admin"], "/api/scans", {"target_id": env["assigned"], "profile": "PASSIVE"})
    assert r.status_code == 201
    execs = r.json()["executions"]
    assert len(execs) == 1 and execs[0]["target_id"] == env["assigned"]


def test_scan_multiple_targets_defined_and_typed(env):
    r = _p(env["admin"], "/api/scans", {
        "target_ids": [env["assigned"]],
        "target_values": ["10.10.7.7", "10.10.8.8"],
        "profile": "PASSIVE",
    })
    assert r.status_code == 201
    assert len(r.json()["executions"]) == 3
    values = {t["value"] for t in env["admin"].get("/api/targets").json()}
    assert {"10.10.5.20", "10.10.7.7", "10.10.8.8"} <= values


def test_duplicate_targets_collapse(env):
    r = _p(env["admin"], "/api/scans", {
        "target_id": env["assigned"],
        "target_values": ["10.10.5.20"],  # same host, by value
        "profile": "PASSIVE",
    })
    assert len(r.json()["executions"]) == 1


def test_typed_value_hitting_a_deny_rule_is_rejected(env):
    r = _p(env["admin"], "/api/scans", {"target_values": ["10.10.9.9"], "profile": "PASSIVE"})
    assert r.status_code == 422
    assert "policy" in r.json()["detail"]


def test_no_target_is_a_422(env):
    assert _p(env["admin"], "/api/scans", {"profile": "PASSIVE"}).status_code == 422


def test_scanner_cannot_scan_an_undefined_host(env):
    with TestClient(create_app()) as sc:
        sc.post("/api/auth/login", json={"username": "scan1", "password": SCAN_PW})
        h = {"X-CSRF-Token": sc.cookies.get("trashscan_csrf")}
        assert sc.post("/api/scans", json={"target_value": "10.10.5.20", "profile": "PASSIVE"},
                       headers=h).status_code == 201
        assert sc.post("/api/scans", json={"target_value": "10.10.8.8", "profile": "PASSIVE"},
                       headers=h).status_code == 403


# --- ports on an active scan ---------------------------------------
def test_active_scan_records_custom_ports(env):
    r = _p(env["admin"], "/api/scans", {
        "target_id": env["assigned"], "profile": "SAFE_ACTIVE",
        "attestation_text": ACTIVE_SCAN_ATTESTATION, "ports": "22,80,443,8000-8010",
    })
    assert r.status_code == 201
    ex_id = r.json()["executions"][0]["id"]
    detail = env["admin"].get(f"/api/scans/{ex_id}").json()
    # approval carries the requested options
    approvals = env["admin"].get("/api/approvals").json()
    opts = next(a for a in approvals if a["execution_id"] == ex_id)["requested_options"]
    assert opts["ports"] == "22,80,443,8000-8010"
    assert detail["state"] == "AWAITING_APPROVAL"


def test_active_scan_rejects_bad_ports(env):
    r = _p(env["admin"], "/api/scans", {
        "target_id": env["assigned"], "profile": "SAFE_ACTIVE",
        "attestation_text": ACTIVE_SCAN_ATTESTATION, "ports": "22,not-a-port",
    })
    assert r.status_code == 422


def test_port_preset_web(env):
    r = _p(env["admin"], "/api/scans", {
        "target_id": env["assigned"], "profile": "SAFE_ACTIVE",
        "attestation_text": ACTIVE_SCAN_ATTESTATION, "port_preset": "WEB",
    })
    ex_id = r.json()["executions"][0]["id"]
    approvals = env["admin"].get("/api/approvals").json()
    opts = next(a for a in approvals if a["execution_id"] == ex_id)["requested_options"]
    assert opts["ports"] == "80,443,8080,8443,8000,8888"
