"""Nmap NSE allowlist: SMB signing, LDAP root DSE, RDP encryption (PRD §12.1).

``smb_signing_finding`` is a pure function shared by the real and fake
adapters, unit-tested directly here, then exercised end-to-end through the
fake pipeline and through XML parsing to confirm the allowlist is actually
wired into a scan and that no other script id is ever surfaced.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import StageInput
from app.adapters.fake import FakeNmapAdapter, _octet
from app.adapters.nmap import (
    NSE_SCRIPTS,
    _parse_xml,
    smb_protocols_finding,
    smb_signing_finding,
    ssl_cert_findings,
)
from app.models import Finding, PrivateCidr, ScanExecution, Target, User
from app.scan_profiles import PROFILES
from app.security import hash_password
from app.worker import runner

# --- smb_signing_finding --------------------------------------------------


def test_smb_signing_flags_disabled_as_medium():
    f = smb_signing_finding("smb-security-mode", "message_signing: disabled (dangerous, but default)",
                             "10.10.1.5")
    assert f is not None
    assert f.rule_id == "smb-signing-not-required"
    assert f.severity == "MEDIUM"


def test_smb_signing_flags_enabled_but_not_required_as_low():
    f = smb_signing_finding("smb2-security-mode", "Message signing enabled but not required",
                             "10.10.1.5")
    assert f is not None
    assert f.severity == "LOW"


def test_smb_signing_enabled_and_required_is_clean():
    assert smb_signing_finding("smb2-security-mode", "Message signing enabled and required",
                               "10.10.1.5") is None


def test_smb_signing_tolerates_unrelated_output():
    assert smb_signing_finding("smb2-security-mode", "", "10.10.1.5") is None
    assert smb_signing_finding("smb2-security-mode", "some unrelated banner", "10.10.1.5") is None


# --- ssl_cert_findings ------------------------------------------------------


def test_ssl_cert_flags_expired_certificate():
    out = "Subject: commonName=x.example.com\nNot valid before: 2019-01-01T00:00:00\nNot valid after:  2020-01-01T00:00:00"
    findings = ssl_cert_findings(out, "10.10.1.5", 636)
    assert [f.rule_id for f in findings] == ["tls-cert-expired"]
    assert findings[0].severity == "HIGH"


def test_ssl_cert_flags_expiring_soon():
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
    out = f"Subject: commonName=x.example.com\nNot valid after:  {soon}"
    findings = ssl_cert_findings(out, "10.10.1.5", 636)
    assert [f.rule_id for f in findings] == ["tls-cert-expiring-soon"]


def test_ssl_cert_healthy_certificate_is_clean():
    out = "Subject: commonName=x.example.com\nNot valid after:  2099-01-01T00:00:00"
    assert ssl_cert_findings(out, "10.10.1.5", 636) == []


def test_ssl_cert_tolerates_missing_or_malformed_output():
    assert ssl_cert_findings("", "10.10.1.5", 636) == []
    assert ssl_cert_findings("no validity line here", "10.10.1.5", 636) == []
    assert ssl_cert_findings("Not valid after:  not-a-date", "10.10.1.5", 636) == []


# --- smb_protocols_finding ---------------------------------------------------


def test_smb_protocols_flags_smbv1():
    out = "dialects: \n  NT LM 0.12 (SMBv1) [dangerous, but default]\n  2.0.2\n  2.1"
    f = smb_protocols_finding(out, "10.10.1.5")
    assert f is not None
    assert f.rule_id == "smb1-enabled"
    assert f.severity == "HIGH"


def test_smb_protocols_clean_when_smbv1_absent():
    out = "dialects: \n  2.0.2\n  2.1\n  3.0\n  3.0.2\n  3.1.1"
    assert smb_protocols_finding(out, "10.10.1.5") is None


def test_smb_protocols_tolerates_unrelated_output():
    assert smb_protocols_finding("", "10.10.1.5") is None


# --- _parse_xml: hostscript + port-level script elements -------------------

_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.10.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="389">
<state state="open"/>
<service name="ldap"/>
<script id="ldap-rootdse" output="namingcontexts: dc=lab,dc=internal"/>
</port>
<port protocol="tcp" portid="3389">
<state state="open"/>
<service name="ms-wbt-server"/>
<script id="rdp-enum-encryption" output="Security layer: RDP, SSL, CredSSP"/>
</port>
<port protocol="tcp" portid="636">
<state state="open"/>
<service name="ldapssl"/>
<script id="ssl-cert" output="Subject: commonName=10.10.1.5&#10;Not valid after:  2020-01-01T00:00:00"/>
</port>
</ports>
<hostscript>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
<script id="smb-protocols" output="dialects: &#10;  NT LM 0.12 (SMBv1) [dangerous, but default]&#10;  2.0.2"/>
<script id="not-on-the-allowlist" output="should never appear"/>
</hostscript>
</host>
</nmaprun>"""


def test_parse_xml_surfaces_allowlisted_scripts_as_observations():
    _, observations, findings, parsed = _parse_xml(_XML)
    assert parsed
    ids = {o.key for o in observations}
    assert ids == {"ldap-rootdse", "rdp-enum-encryption", "smb2-security-mode", "ssl-cert",
                   "smb-protocols"}
    assert "not-on-the-allowlist" not in ids


def test_parse_xml_turns_script_output_into_findings():
    _, _, findings, _ = _parse_xml(_XML)
    ids = {f.rule_id for f in findings}
    assert ids == {"smb-signing-not-required", "tls-cert-expired", "smb1-enabled"}


def test_nse_scripts_allowlist_is_never_a_category_or_wildcard():
    for name in NSE_SCRIPTS:
        assert "*" not in name
        assert not name.startswith("brute")
        assert "brute" not in name


# --- profile wiring ---------------------------------------------------------


def test_only_active_profiles_enable_nse_scripts():
    assert PROFILES["PASSIVE"].nmap_nse_scripts is False
    assert PROFILES["SAFE_ACTIVE"].nmap_nse_scripts is True
    assert PROFILES["STANDARD_ACTIVE"].nmap_nse_scripts is True


# --- fake pipeline end-to-end -----------------------------------------------


def test_fake_nmap_adapter_only_emits_nse_observations_when_enabled():
    inp_off = StageInput(stage="nmap", target_kind="CIDR", target_value="10.10.1.0/24",
                         profile="SAFE_ACTIVE", hosts=["10.10.1.5"], options={"nse_scripts": False})
    out_off = FakeNmapAdapter().run(inp_off)
    assert all(o.kind != "NSE" for o in out_off.observations)

    inp_on = StageInput(stage="nmap", target_kind="CIDR", target_value="10.10.1.0/24",
                        profile="SAFE_ACTIVE", hosts=["10.10.1.5"], options={"nse_scripts": True})
    out_on = FakeNmapAdapter().run(inp_on)
    assert any(o.kind == "NSE" for o in out_on.observations)


def _smb_signing_ip() -> str:
    """Find an IP in the lab /16 for which the fake adapter's deterministic
    hash seeds both an SMB service and a "not required" signing result, so
    the end-to-end test below doesn't depend on which IP happens to qualify."""
    for third in range(1, 255):
        ip = f"10.10.1.{third}"
        if (_octet(ip, "smb") % 3) == 0 and (_octet(ip, "smb-sign") % 2) == 0:
            return ip
    raise AssertionError("no candidate IP found — fake adapter's hash logic may have changed")


@pytest.fixture
def ip_lab(db):
    u = User(username="nse_adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    ip = _smb_signing_ip()
    t = Target(kind="IPV4", value=ip)
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id, "ip": ip}


def test_active_scan_can_surface_an_smb_signing_finding(db, ip_lab):
    ex = ScanExecution(target_id=ip_lab["target"], requested_by_id=ip_lab["user"],
                       profile="SAFE_ACTIVE", classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    db.expire_all()
    findings = db.query(Finding).filter(Finding.target_id == ip_lab["target"]).all()
    # The fake pipeline is deterministic per-IP; this address seeds an SMB
    # service with signing "enabled but not required" (see FakeNmapAdapter).
    assert any(f.rule_id == "smb-signing-not-required" for f in findings)
