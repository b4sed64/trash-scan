"""External OSINT lookups (crt.sh CT logs, WHOIS/RDAP) — off by default.

The real network calls are never exercised here: ``set_fetcher`` injects a
canned responder (the same pattern ``services.scope_db.set_resolver`` uses for
DNS), so these tests run fully offline while still exercising the real
adapter's control flow end to end.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from app.adapters import osint
from app.adapters.base import StageInput
from app.adapters.osint import (
    OsintAdapter,
    parse_crt_sh,
    parse_rdap,
    registration_expiry_finding,
    set_fetcher,
)

CRT_SH_SAMPLE = [
    {"name_value": "example.com\nwww.example.com"},
    {"name_value": "api.example.com"},
    {"name_value": "unrelated-example.com"},  # not a subdomain — must be excluded
]

RDAP_SAMPLE = {
    "entities": [{
        "roles": ["registrar"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar LLC"]]],
    }],
    "events": [
        {"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2099-03-01T00:00:00Z"},
    ],
    "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
}


def _inp(target_kind: str = "DOMAIN", target_value: str = "example.com", **kw) -> StageInput:
    return StageInput(stage="osint", target_kind=target_kind, target_value=target_value,
                      profile="PASSIVE", **kw)


# --- pure parsing -----------------------------------------------------------

def test_parse_crt_sh_keeps_only_the_domain_and_its_subdomains():
    hosts = parse_crt_sh(CRT_SH_SAMPLE, "example.com")
    assert hosts == ["api.example.com", "example.com", "www.example.com"]


def test_parse_crt_sh_tolerates_garbage():
    assert parse_crt_sh(None, "example.com") == []
    assert parse_crt_sh("not-a-list", "example.com") == []
    assert parse_crt_sh([{"name_value": None}], "example.com") == []


def test_parse_rdap_extracts_registrar_dates_and_nameservers():
    rdap = parse_rdap(RDAP_SAMPLE)
    assert rdap["registrar"] == "Example Registrar LLC"
    assert rdap["created"] == "2015-03-01T00:00:00Z"
    assert rdap["expires"] == "2099-03-01T00:00:00Z"
    assert rdap["nameservers"] == ["ns1.example.com", "ns2.example.com"]


def test_parse_rdap_tolerates_garbage():
    assert parse_rdap(None) == {}
    assert parse_rdap({}) == {"registrar": "", "created": "", "expires": "", "nameservers": []}


def test_registration_expiry_finding_none_when_healthy():
    rdap = {"expires": "2099-01-01T00:00:00Z", "registrar": "x"}
    assert registration_expiry_finding(rdap, "example.com") is None


def test_registration_expiry_finding_expiring_soon():
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = registration_expiry_finding({"expires": soon, "registrar": "x"}, "example.com")
    assert f is not None
    assert f.rule_id == "osint-domain-registration-expiring-soon"
    assert f.severity == "MEDIUM"


def test_registration_expiry_finding_already_expired():
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = registration_expiry_finding({"expires": past, "registrar": "x"}, "example.com")
    assert f is not None
    assert f.rule_id == "osint-domain-registration-expired"
    assert f.severity == "HIGH"


def test_registration_expiry_finding_no_data():
    assert registration_expiry_finding({}, "example.com") is None


# --- the real adapter, network fully mocked out --------------------------

def test_adapter_is_a_noop_when_disabled_by_default(monkeypatch):
    monkeypatch.setattr(osint, "get_settings", lambda: SimpleNamespace(enable_external_osint=False))
    out = OsintAdapter().run(_inp())
    assert out.ok is True
    assert out.assets == [] and out.observations == [] and out.findings == []
    assert "disabled" in out.note


def test_adapter_is_a_noop_for_non_domain_targets(monkeypatch):
    monkeypatch.setattr(osint, "get_settings", lambda: SimpleNamespace(enable_external_osint=True))
    out = OsintAdapter().run(_inp(target_kind="IPV4", target_value="10.10.5.20"))
    assert out.assets == [] and out.findings == []


def test_adapter_enabled_surfaces_subdomains_and_expiry_finding(monkeypatch):
    monkeypatch.setattr(osint, "get_settings", lambda: SimpleNamespace(enable_external_osint=True))

    def fake_fetch(url: str):
        if "crt.sh" in url:
            return CRT_SH_SAMPLE
        if "rdap.org" in url:
            soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return {**RDAP_SAMPLE, "events": [{"eventAction": "expiration", "eventDate": soon}]}
        return None

    set_fetcher(fake_fetch)
    try:
        out = OsintAdapter().run(_inp())
    finally:
        set_fetcher(None)

    assert {a.value for a in out.assets} >= {"api.example.com", "www.example.com"}
    assert all(a.source == "crt.sh" for a in out.assets)
    assert any(o.key == "whois-registrar" for o in out.observations)
    assert any(f.rule_id == "osint-domain-registration-expiring-soon" for f in out.findings)
    assert out.incomplete is False


def test_adapter_marks_incomplete_when_a_lookup_fails(monkeypatch):
    monkeypatch.setattr(osint, "get_settings", lambda: SimpleNamespace(enable_external_osint=True))
    set_fetcher(lambda url: None)
    try:
        out = OsintAdapter().run(_inp())
    finally:
        set_fetcher(None)
    assert out.incomplete is True
    assert "failed" in out.note or "timed out" in out.note


# --- the fake adapter (always deterministic, no flag needed) --------------

def test_fake_adapter_is_deterministic_and_needs_no_flag():
    from app.adapters.fake import FakeOsintAdapter

    a = FakeOsintAdapter().run(_inp())
    b = FakeOsintAdapter().run(_inp())
    assert [x.value for x in a.assets] == [x.value for x in b.assets]
    assert any(o.key == "whois-registrar" for o in a.observations)
