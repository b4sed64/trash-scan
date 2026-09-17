"""TLS/certificate posture and passive DNS-record (SPF/DMARC/CAA) enrichment.

Both rule sets are pure functions shared by the real and fake adapters, so they
are unit-tested directly here, then exercised end-to-end through the fake
pipeline to confirm they are actually wired into a scan.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import DiscoveredObservation
from app.adapters.dnsx import dns_posture_findings
from app.adapters.httpx import tls_findings
from app.models import Finding, PrivateCidr, ScanExecution, Target, User
from app.security import hash_password
from app.services.scope_db import set_resolver
from app.worker import runner

# --- tls_findings ------------------------------------------------------


def test_tls_findings_flags_expired_certificate():
    tls = {"port": "443", "expired": True, "subject_cn": "x.example.com",
           "issuer_cn": "Bad CA", "not_after": "2020-01-01T00:00:00Z", "serial": "1"}
    ids = {f.rule_id for f in tls_findings(tls, "x.example.com")}
    assert "tls-cert-expired" in ids


def test_tls_findings_flags_expiring_soon_but_not_expired():
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tls = {"port": "443", "expired": False, "not_after": soon, "serial": "2"}
    ids = {f.rule_id for f in tls_findings(tls, "x.example.com")}
    assert ids == {"tls-cert-expiring-soon"}


def test_tls_findings_flags_self_signed_and_mismatch():
    tls = {"port": "443", "self_signed": True, "mismatched": True, "serial": "3",
           "not_after": "2099-01-01T00:00:00Z"}
    ids = {f.rule_id for f in tls_findings(tls, "x.example.com")}
    assert {"tls-self-signed", "tls-hostname-mismatch"} <= ids


def test_tls_findings_deprecated_protocol_severity_scales_with_age():
    base = {"port": "443", "not_after": "2099-01-01T00:00:00Z"}
    tls10 = tls_findings({**base, "tls_version": "tls10"}, "x.example.com")
    ssl30 = tls_findings({**base, "tls_version": "ssl30"}, "x.example.com")
    assert next(f.severity for f in tls10 if f.rule_id == "tls-deprecated-protocol") == "MEDIUM"
    assert next(f.severity for f in ssl30 if f.rule_id == "tls-deprecated-protocol") == "HIGH"


def test_tls_findings_healthy_certificate_is_clean():
    tls = {"port": "443", "tls_version": "tls13", "expired": False, "self_signed": False,
           "mismatched": False, "not_after": "2099-01-01T00:00:00Z"}
    assert tls_findings(tls, "x.example.com") == []


def test_tls_findings_tolerates_missing_fields():
    assert tls_findings({}, "x.example.com") == []
    assert tls_findings({"port": "443"}, "x.example.com") == []


# --- dns_posture_findings ------------------------------------------------


def _obs(key: str, value: str, asset: str) -> DiscoveredObservation:
    return DiscoveredObservation(kind="DNS_RECORD", key=key, value=value, source="dnsx",
                                 asset_value=asset)


def test_dns_posture_flags_everything_missing_on_a_bare_domain():
    ids = {f.rule_id for f in dns_posture_findings([], "example.com")}
    assert {"dns-spf-missing", "dns-dmarc-missing", "dns-caa-missing"} <= ids


def test_dns_posture_flags_permissive_spf_and_monitor_only_dmarc():
    obs = [
        _obs("TXT", "v=spf1 include:_spf.example.com +all", "example.com"),
        _obs("TXT", "v=DMARC1; p=none;", "_dmarc.example.com"),
        _obs("CAA", '0 issue "letsencrypt.org"', "example.com"),
    ]
    ids = {f.rule_id for f in dns_posture_findings(obs, "example.com")}
    assert ids == {"dns-spf-permissive", "dns-dmarc-policy-none"}


def test_dns_posture_clean_when_well_configured():
    obs = [
        _obs("TXT", "v=spf1 include:_spf.example.com ~all", "example.com"),
        _obs("TXT", "v=DMARC1; p=reject;", "_dmarc.example.com"),
        _obs("CAA", '0 issue "letsencrypt.org"', "example.com"),
    ]
    assert dns_posture_findings(obs, "example.com") == []


def test_dns_posture_only_looks_at_the_target_domain():
    # a sibling/child hostname's TXT record must not satisfy the apex's SPF check
    obs = [_obs("TXT", "v=spf1 ~all", "other.example.com")]
    ids = {f.rule_id for f in dns_posture_findings(obs, "example.com")}
    assert "dns-spf-missing" in ids


# --- end-to-end through the fake pipeline --------------------------------


@pytest.fixture
def domain_lab(db):
    u = User(username="enr_adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="DOMAIN", value="lab.example.com")
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def test_active_scan_against_a_domain_surfaces_dns_findings(db, domain_lab):
    ex = ScanExecution(target_id=domain_lab["target"], requested_by_id=domain_lab["user"],
                       profile="SAFE_ACTIVE", classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    set_resolver(lambda _domain: ["10.10.5.20"])  # in-scope, so the launch proceeds
    try:
        assert runner.execute(ex.id) == "COMPLETED"
    finally:
        set_resolver(None)
    db.expire_all()
    findings = db.query(Finding).filter(Finding.target_id == domain_lab["target"]).all()
    tools = {f.source_tool for f in findings}
    rule_ids = {f.rule_id for f in findings}
    assert "dnsx" in tools
    assert "dns-spf-missing" in rule_ids  # the fake dnsx adapter emits no TXT records


def test_passive_scan_against_a_domain_also_surfaces_dns_findings(db, domain_lab):
    ex = ScanExecution(target_id=domain_lab["target"], requested_by_id=domain_lab["user"],
                       profile="PASSIVE", classification="PASSIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    db.expire_all()
    rule_ids = {f.rule_id for f in
                db.query(Finding).filter(Finding.target_id == domain_lab["target"]).all()}
    assert "dns-dmarc-missing" in rule_ids
