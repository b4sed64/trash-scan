"""Integrated release acceptance (PRD v2 Phase 23).

Cross-cutting release invariants, distinct from the per-phase tests:
- the exploitation/session modes default OFF (only offline assessment is on);
- the published capability matrix derives ``enabled`` from flags ONLY, so no
  mode is ever enabled by a (possibly fake) result, and fake-backed modes stay
  fake even when enabled;
- synthetic scan data is labelled as such (fake/demo data separation), in the
  provenance block and the report export;
- the matrix is published through the API to any authenticated user.
"""
from __future__ import annotations

import pytest

from app.config import Settings
from app.models import Target
from app.services import capabilities

ADMIN_PW = "admin-password-123"

_GATED = ("lab_checks", "lab_proof", "guided_sessions", "lab_terminal")


def _csrf(client):
    return client.cookies.get("trashscan_csrf")


def _post(client, url, json=None):
    return client.post(url, json=json, headers={"X-CSRF-Token": _csrf(client)})


@pytest.fixture
def admin_client(client):
    assert client.get("/api/auth/setup-status").json()["needs_setup"] is True
    r = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 201
    return client


# --- default feature flags -------------------------------------------------


def test_exploitation_and_session_modes_default_off():
    f = Settings.model_fields
    assert f["enable_lab_checks"].default is False
    assert f["enable_lab_proof"].default is False
    assert f["enable_guided_sessions"].default is False
    assert f["enable_lab_terminal"].default is False
    # the only exploitability mode on by default is the offline analytical one
    assert f["enable_exploitability_assessment"].default is True
    assert f["enable_external_osint"].default is False


# --- capability matrix integrity ------------------------------------------


def test_matrix_enabled_mirrors_flags_and_gated_modes_are_fake():
    off = Settings(enable_lab_checks=False, enable_lab_proof=False,
                   enable_guided_sessions=False, enable_lab_terminal=False)
    m = capabilities.support_matrix(off)
    caps = {c["key"]: c for c in m["capabilities"]}
    for key in _GATED:
        assert caps[key]["enabled"] is False
        assert caps[key]["backing"] == capabilities.FAKE
        assert caps[key]["real_lab_gate"]  # a real-lab gate is named
    assert set(m["disabled_optional_modes"]) >= set(_GATED)
    assert set(m["fake_backed_modes"]) >= set(_GATED)


def test_enabling_a_flag_enables_only_that_mode_and_does_not_make_it_real():
    on = Settings(enable_lab_terminal=True)
    caps = {c["key"]: c for c in capabilities.support_matrix(on)["capabilities"]}
    assert caps["lab_terminal"]["enabled"] is True
    assert caps["lab_proof"]["enabled"] is False  # unrelated mode stays off
    # a flag flips visibility, never backing: the terminal is still fake here
    assert caps["lab_terminal"]["backing"] == capabilities.FAKE


def test_assessment_is_offline_backed():
    caps = {c["key"]: c for c in capabilities.support_matrix(Settings())["capabilities"]}
    assert caps["exploitability_assessment"]["backing"] == capabilities.OFFLINE


# --- fake / demo data separation ------------------------------------------


def test_scanner_mode_marks_data_synthetic():
    assert capabilities.data_provenance(Settings(scanner_mode="fake"))["synthetic"] is True
    assert capabilities.data_provenance(Settings(scanner_mode="real"))["synthetic"] is False


def test_report_export_labels_synthetic_data(admin_client, db):
    t = Target(kind="IPV4", value="10.10.7.21")
    db.add(t)
    db.commit()
    r = admin_client.get(f"/api/targets/{t.id}/report.json")
    assert r.status_code == 200, r.text
    prov = r.json()["data_provenance"]
    # the test environment runs the fake scanner, so data is synthetic
    assert prov["synthetic"] is True
    assert prov["scanner_mode"] == "fake"


# --- publication ----------------------------------------------------------


def test_capability_matrix_published_via_api(admin_client):
    r = admin_client.get("/api/capabilities")
    assert r.status_code == 200, r.text
    body = r.json()
    keys = {c["key"] for c in body["capabilities"]}
    assert {"scanning", "exploitability_assessment", *_GATED} <= keys
    assert body["data_provenance"]["synthetic"] is True


def test_capabilities_requires_authentication(client):
    assert client.get("/api/capabilities").status_code == 401
