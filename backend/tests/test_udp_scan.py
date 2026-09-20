"""UDP scan (Standard active only) and the SNMP/NetBIOS scripts it unlocks.

UDP scanning needs the same raw-packet capability as SYN scan/OS detection
(``TRASHSCAN_ALLOW_RAW_PACKET`` + ``NET_RAW``), off by default. ``snmp-sysdescr``
and ``nbstat`` both need a UDP port open, so they are only ever added to
Nmap's ``--script`` argument when the UDP scan itself is enabled — this file
checks that gate directly against the real adapter's argv construction, not
just the fake pipeline.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.adapters.base import StageInput
from app.adapters.fake import FakeNmapAdapter
from app.adapters.nmap import NSE_SCRIPTS, NmapAdapter, _UDP_ONLY_SCRIPTS, snmp_public_finding
from app.scan_profiles import PROFILES

# --- snmp_public_finding -----------------------------------------------------


def test_snmp_public_finding_flags_any_successful_response():
    f = snmp_public_finding("Cisco IOS Software, lab switch\n  System uptime: 1 day", "10.10.1.5")
    assert f is not None
    assert f.rule_id == "snmp-public-community-exposed"
    assert f.severity == "MEDIUM"
    assert f.port == 161 and f.protocol == "udp"


def test_snmp_public_finding_clean_when_no_response():
    assert snmp_public_finding("", "10.10.1.5") is None
    assert snmp_public_finding(None, "10.10.1.5") is None


# --- allowlist membership -----------------------------------------------------


def test_udp_only_scripts_are_a_subset_of_the_full_allowlist():
    assert _UDP_ONLY_SCRIPTS <= NSE_SCRIPTS
    assert _UDP_ONLY_SCRIPTS == {"snmp-sysdescr", "nbstat"}


def test_only_standard_active_enables_udp_scan():
    assert PROFILES["PASSIVE"].nmap_udp_scan is False
    assert PROFILES["SAFE_ACTIVE"].nmap_udp_scan is False
    assert PROFILES["STANDARD_ACTIVE"].nmap_udp_scan is True


# --- real adapter argv gating -------------------------------------------------


def _settings(*, allow_raw_packet: bool) -> SimpleNamespace:
    return SimpleNamespace(
        ports_for_profile=lambda profile: "80,443",
        timing_for_profile=lambda profile: "T3",
        allow_raw_packet=allow_raw_packet,
        standard_udp_ports="161,137",
    )


def _run(monkeypatch, tmp_path, *, allow_raw_packet: bool, udp_scan: bool, nse_scripts: bool = True,
         udp_ports: str | None = None):
    import app.adapters.nmap as nmap_module
    monkeypatch.setattr(nmap_module, "get_settings", lambda: _settings(allow_raw_packet=allow_raw_packet))
    options = {"syn": False, "os_detection": False, "service_detection": True,
               "nse_scripts": nse_scripts, "udp_scan": udp_scan}
    if udp_ports is not None:
        options["udp_ports"] = udp_ports
    inp = StageInput(
        stage="nmap", target_kind="IPV4", target_value="127.0.0.1", profile="STANDARD_ACTIVE",
        hosts=["127.0.0.1"], result_dir=str(tmp_path), options=options,
    )
    return NmapAdapter().run(inp)


def test_udp_ports_option_overrides_the_configured_default(monkeypatch, tmp_path):
    """An admin-defined UDP PortSet, threaded through as ``udp_ports``, takes
    over from ``TRASHSCAN_STANDARD_UDP_PORTS`` for this scan."""
    out = _run(monkeypatch, tmp_path, allow_raw_packet=True, udp_scan=True, udp_ports="9999")
    port_arg = out.args[out.args.index("-p") + 1]
    assert port_arg == "T:80,443,U:9999"


def test_udp_scan_disabled_by_default_even_if_profile_requests_it(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, allow_raw_packet=False, udp_scan=True)
    assert "-sU" not in out.args
    assert not any(a.startswith("U:") or ",U:" in a for a in out.args)
    scripts_arg = out.args[out.args.index("--script") + 1]
    assert not (_UDP_ONLY_SCRIPTS & set(scripts_arg.split(",")))


def test_udp_scan_enabled_when_capability_and_profile_both_allow_it(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, allow_raw_packet=True, udp_scan=True)
    assert "-sU" in out.args
    port_arg = out.args[out.args.index("-p") + 1]
    assert port_arg == "T:80,443,U:161,137"
    scripts_arg = out.args[out.args.index("--script") + 1]
    assert _UDP_ONLY_SCRIPTS <= set(scripts_arg.split(","))


def test_udp_scan_stays_off_when_profile_does_not_request_it(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, allow_raw_packet=True, udp_scan=False)
    assert "-sU" not in out.args
    port_arg = out.args[out.args.index("-p") + 1]
    assert port_arg == "80,443"


# --- fake pipeline -------------------------------------------------------


def test_fake_nmap_adapter_only_emits_udp_findings_when_udp_scan_enabled():
    inp_off = StageInput(stage="nmap", target_kind="CIDR", target_value="10.10.1.0/24",
                         profile="STANDARD_ACTIVE", hosts=["10.10.1.5"],
                         options={"nse_scripts": True, "udp_scan": False})
    out_off = FakeNmapAdapter().run(inp_off)
    assert all(o.key not in ("snmp-sysdescr", "nbstat") for o in out_off.observations)

    inp_on = StageInput(stage="nmap", target_kind="CIDR", target_value="10.10.1.0/24",
                        profile="STANDARD_ACTIVE", hosts=["10.10.1.5"],
                        options={"nse_scripts": True, "udp_scan": True})
    out_on = FakeNmapAdapter().run(inp_on)
    keys = {o.key for o in out_on.observations}
    assert keys & {"snmp-sysdescr", "nbstat"}
