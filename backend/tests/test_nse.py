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
from app.adapters.nmap import NSE_SCRIPTS, _parse_xml, smb_signing_finding
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
</ports>
<hostscript>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
<script id="not-on-the-allowlist" output="should never appear"/>
</hostscript>
</host>
</nmaprun>"""


def test_parse_xml_surfaces_allowlisted_scripts_as_observations():
    _, observations, findings, parsed = _parse_xml(_XML)
    assert parsed
    ids = {o.key for o in observations}
    assert ids == {"ldap-rootdse", "rdp-enum-encryption", "smb2-security-mode"}
    assert "not-on-the-allowlist" not in ids


def test_parse_xml_turns_smb_signing_output_into_a_finding():
    _, _, findings, _ = _parse_xml(_XML)
    assert [f.rule_id for f in findings] == ["smb-signing-not-required"]


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
