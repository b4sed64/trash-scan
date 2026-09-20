"""Nmap adapter — TCP port discovery and service estimation (PRD §12.1).

Hard restrictions enforced here:
  * no spoofing, decoys, fragmentation or timing-evasion options;
  * NSE scripts are limited to a fixed, Administrator-reviewed allowlist of
    safe/discovery-only configuration-disclosure scripts (PRD §12.1) — never a
    category or wildcard selection, and never a credential, brute-force,
    exploit, intrusive, or denial-of-service script;
  * no user-supplied flags — every argument comes from the profile + config;
  * SYN scan (``-sS``), OS detection (``-O``), and UDP scan (``-sU``) are only
    added when ``allow_raw_packet`` is enabled; otherwise a TCP connect scan
    (``-sT``) is used, OS detection is skipped, and no UDP ports are scanned.
  * UDP scanning (Standard active only) is a fixed, curated port list
    (``settings.standard_udp_ports``), never a broad/arbitrary sweep, and exists
    specifically to let ``snmp-sysdescr``/``nbstat`` run — not general UDP
    service discovery.
  * targets are the pre-resolved in-scope IPs, never a hostname.

``smb2-security-mode``/``smb-security-mode`` report whether SMB message signing
is enforced; ``ldap-rootdse`` reads the anonymously-queryable LDAP root DSE;
``rdp-enum-encryption`` reports which RDP security layers a host offers;
``ssl-cert`` reads a certificate's validity period on non-HTTP TLS services
(LDAPS, SMTP-STARTTLS, RDP-over-TLS — httpx's ``-tls-grab`` only ever sees
HTTP(S)); ``smb-protocols`` lists which SMB dialects a server accepts;
``snmp-sysdescr`` reads system info over SNMP using the default ``public``
read-only community string (nmap's own ``nselib/snmp.lua`` only ever tries
that one well-known default, never a list — a single default-credential
check, the same category as an anonymous LDAP bind, not a guessing
campaign); ``nbstat`` reads a host's self-announced NetBIOS name/user/MAC.
All eight are Nmap-categorized ``safe``/``discovery``/``default`` with no
exception needed. ``smb_signing_finding``, ``ssl_cert_findings``,
``smb_protocols_finding``, and ``snmp_public_finding`` turn their scripts'
output into actionable findings the same way ``httpx.tls_findings`` does for
TLS; ``ldap-rootdse``, ``rdp-enum-encryption``, and ``nbstat`` surface as
observations only, since their output is asset-identification data rather
than a posture verdict, or isn't stable enough to key a severity-ranked rule
off with confidence.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re

import defusedxml.ElementTree as ET
from defusedxml.ElementTree import ParseError

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_NMAP,
    DiscoveredFinding,
    DiscoveredObservation,
    DiscoveredService,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_NMAP_BIN", "nmap")
_WEBBISH = {"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http"}

# Fixed NSE allowlist — passed to ``--script`` by exact name only, never a
# category or wildcard, so a script's own "dependencies" (e.g. smb-security-mode
# lists smb-brute) can never cause Nmap to also schedule a brute-force script:
# Nmap's dependency system only orders scripts that were *both* already
# selected, it never selects one on its own.
NSE_SCRIPTS = frozenset({
    "smb2-security-mode", "smb-security-mode", "ldap-rootdse", "rdp-enum-encryption",
    "ssl-cert", "smb-protocols", "snmp-sysdescr", "nbstat",
})
# snmp-sysdescr/nbstat both need UDP ports open (SNMP/161, NetBIOS/137), so
# they are only ever added to --script when the UDP scan itself is enabled
# (Standard active + allow_raw_packet) — never requested, and so never run,
# otherwise.
_UDP_ONLY_SCRIPTS = frozenset({"snmp-sysdescr", "nbstat"})
_SIGNING_SCRIPTS = {"smb2-security-mode", "smb-security-mode"}
_EXPIRING_SOON_DAYS = 30
_NOT_VALID_AFTER_RE = re.compile(r"Not valid after:\s*([0-9T:\-]+)")


def _rule_hash(rule_id: str, version: str = "v1") -> str:
    """A stable stand-in for a Nuclei template hash, for findings this adapter
    derives itself rather than sourcing from a template."""
    return hashlib.sha256(f"trashscan-internal-rule:{rule_id}:{version}".encode()).hexdigest()


def smb_signing_finding(script_id: str, output: str, host: str) -> DiscoveredFinding | None:
    """Classify smb2-security-mode/smb-security-mode output into a finding.

    Nmap's own phrasing for this has been stable for years: the output always
    contains the word "signing" plus one of "enabled and required" (best
    practice — nothing to flag), "enabled but not required", or "disabled".
    """
    text = (output or "").lower()
    if "signing" not in text:
        return None
    if "enabled and required" in text:
        return None
    if "disabled" in text:
        severity, state = "MEDIUM", "disabled"
    elif "not required" in text or "not supported" in text:
        severity, state = "LOW", "not required"
    else:
        return None
    return DiscoveredFinding(
        rule_id="smb-signing-not-required", template_hash=_rule_hash("smb-signing-not-required"),
        severity=severity, name="SMB Signing Not Enforced",
        description=(
            "The SMB server does not require message signing. Unsigned SMB traffic can be "
            "tampered with or relayed by an attacker positioned on the network."
        ),
        asset_value=host, matched_at=f"smb://{host}", matcher_name=script_id,
        evidence_key=f"{script_id}:signing:{state}", evidence_summary=(output or "").strip()[:400],
        evidence={"script": script_id, "output": (output or "")[:1000]},
    )


def ssl_cert_findings(output: str, host: str, port: int | None) -> list[DiscoveredFinding]:
    """Parse ssl-cert's "Not valid after: <ISO time>" line — printed at Nmap's
    default verbosity, no ``-v`` needed. Nmap reports the certificate's own
    notAfter time with no UTC offset; treated as UTC here, matching how
    certificates themselves encode validity (UTCTime/GeneralizedTime)."""
    m = _NOT_VALID_AFTER_RE.search(output or "")
    if not m:
        return []
    try:
        expiry = dt.datetime.fromisoformat(m.group(1)).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return []
    now = dt.datetime.now(dt.timezone.utc)
    matched_at = f"tls://{host}:{port}" if port else f"tls://{host}"

    def _mk(rule_id: str, severity: str, name: str, description: str, evidence_key: str) -> DiscoveredFinding:
        return DiscoveredFinding(
            rule_id=rule_id, template_hash=_rule_hash(rule_id), severity=severity, name=name,
            description=description, asset_value=host, matched_at=matched_at,
            matcher_name="ssl-cert", port=port, protocol="tcp",
            evidence_key=evidence_key, evidence_summary=(output or "").strip()[:400],
            evidence={"script": "ssl-cert", "not_valid_after": m.group(1)},
        )

    if expiry < now:
        return [_mk(
            "tls-cert-expired", "HIGH", "TLS Certificate Expired",
            "The presented certificate's validity period has ended.",
            evidence_key=f"expired:{host}:{port}",
        )]
    days_left = (expiry - now).days
    if days_left <= _EXPIRING_SOON_DAYS:
        return [_mk(
            "tls-cert-expiring-soon", "MEDIUM", "TLS Certificate Expiring Soon",
            f"The certificate expires within {_EXPIRING_SOON_DAYS} days.",
            evidence_key=f"expiring:{host}:{port}",
        )]
    return []


def smb_protocols_finding(output: str, host: str) -> DiscoveredFinding | None:
    """SMBv1 is the dialect implicated in EternalBlue/WannaCry. Nmap's own
    smb-protocols script marks it "[dangerous, but default]" in its output
    when a server still accepts it — that literal marker is the signal."""
    text = output or ""
    if "SMBv1" not in text or "dangerous" not in text.lower():
        return None
    return DiscoveredFinding(
        rule_id="smb1-enabled", template_hash=_rule_hash("smb1-enabled"),
        severity="HIGH", name="SMBv1 Enabled",
        description=(
            "The SMB server still accepts the SMBv1 dialect, which has known serious "
            "vulnerabilities (e.g. EternalBlue) and should be disabled."
        ),
        asset_value=host, matched_at=f"smb://{host}", matcher_name="smb-protocols",
        evidence_key="smb1-enabled", evidence_summary=text.strip()[:400],
        evidence={"script": "smb-protocols", "output": text[:1000]},
    )


def snmp_public_finding(output: str, host: str) -> DiscoveredFinding | None:
    """snmp-sysdescr succeeding at all means the SNMP agent accepted the
    well-known default "public" read-only community string — nmap's snmp
    library only ever tries that one default, never a list (verified against
    nselib/snmp.lua's ``o.community = community or "public"``), so this is a
    single default-credential check, not a guessing campaign."""
    text = (output or "").strip()
    if not text:
        return None
    return DiscoveredFinding(
        rule_id="snmp-public-community-exposed",
        template_hash=_rule_hash("snmp-public-community-exposed"),
        severity="MEDIUM", name="SNMP Public Community String Accepted",
        description=(
            "The SNMP agent accepted the default 'public' read-only community string, "
            "disclosing system information without any real authentication."
        ),
        asset_value=host, matched_at=f"snmp://{host}:161", matcher_name="snmp-sysdescr",
        port=161, protocol="udp",
        evidence_key="snmp-public-community-exposed", evidence_summary=text[:400],
        evidence={"script": "snmp-sysdescr", "output": text[:1000]},
    )


class NmapAdapter:
    stage = STAGE_NMAP
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN, "--version")

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="nmap", tool_version=self.tool_version())
        settings = get_settings()
        want_syn = bool(inp.options.get("syn"))
        want_os = bool(inp.options.get("os_detection"))
        want_service = bool(inp.options.get("service_detection", True))
        want_udp = bool(inp.options.get("udp_scan")) and settings.allow_raw_packet

        scan_targets = list(inp.hosts) or ([inp.target_value] if inp.target_kind == "CIDR" else [])
        scan_targets = [t for t in scan_targets if _is_ip_or_cidr(t)]
        if not scan_targets:
            out.note = "no resolved in-scope IPs to scan"
            return out

        outfile = os.path.join(inp.result_dir, "nmap.xml")
        ports = str(inp.options.get("ports") or settings.ports_for_profile(inp.profile))
        timing = settings.timing_for_profile(inp.profile)
        udp_ports = str(inp.options.get("udp_ports") or settings.standard_udp_ports)
        port_spec = f"T:{ports},U:{udp_ports}" if want_udp else ports

        argv = [BIN, "-oX", outfile, "-Pn", "-n", f"-{timing}", "--host-timeout", "1800s",
                "--max-retries", "2", "-p", port_spec]

        if want_syn and settings.allow_raw_packet:
            argv.append("-sS")
        else:
            argv.append("-sT")
        if want_udp:
            argv.append("-sU")
        if want_service:
            argv += ["-sV", "--version-intensity", "2"]
        if want_os and settings.allow_raw_packet:
            argv += ["-O", "--osscan-limit"]
        if inp.options.get("nse_scripts"):
            scripts = NSE_SCRIPTS if want_udp else (NSE_SCRIPTS - _UDP_ONLY_SCRIPTS)
            argv += ["--script", ",".join(sorted(scripts)), "--script-timeout", "30s"]

        argv += scan_targets
        out.args = argv[1:]

        try:
            res = run_tool(
                argv, timeout_seconds=int(inp.limits.get("stage_timeout", 1800)),
                cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"),
            )
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "nmap binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        xml_text = _read(outfile) or res.stdout.decode("utf-8", errors="replace")
        services, observations, findings, parsed = _parse_xml(xml_text)
        out.services = services
        out.observations = observations
        out.findings = findings
        out.ok = parsed and res.returncode == 0
        if not parsed:
            out.incomplete = True
            out.note = "nmap XML was missing or unparseable"
        return out


def _is_ip_or_cidr(v: str) -> bool:
    import ipaddress

    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _read(path: str) -> str | None:
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    return None


def _script_observation(script_id: str, output: str, host: str) -> DiscoveredObservation:
    value = (output or "").strip().replace("\n", " ")
    value = " ".join(value.split())[:400]
    return DiscoveredObservation(
        kind="NSE", key=script_id, value=value or "(no output)", source="nmap", asset_value=host,
    )


def _findings_for_script(script_id: str, output: str, host: str, port: int | None) -> list[DiscoveredFinding]:
    if script_id in _SIGNING_SCRIPTS:
        f = smb_signing_finding(script_id, output, host)
        return [f] if f else []
    if script_id == "ssl-cert":
        return ssl_cert_findings(output, host, port)
    if script_id == "smb-protocols":
        f = smb_protocols_finding(output, host)
        return [f] if f else []
    if script_id == "snmp-sysdescr":
        f = snmp_public_finding(output, host)
        return [f] if f else []
    return []


def _parse_xml(text: str) -> tuple[list[DiscoveredService], list[DiscoveredObservation], list[DiscoveredFinding], bool]:
    services: list[DiscoveredService] = []
    observations: list[DiscoveredObservation] = []
    findings: list[DiscoveredFinding] = []
    if not text or "<nmaprun" not in text:
        return services, observations, findings, False
    try:
        root = ET.fromstring(text)
    except ParseError:
        # Truncated output: salvage complete <host> blocks.
        cut = text.rfind("</host>")
        if cut == -1:
            return services, observations, findings, False
        try:
            root = ET.fromstring(text[: cut + len("</host>")] + "</nmaprun>")
        except ParseError:
            return services, observations, findings, False

    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state not in ("open", "open|filtered"):
                    continue
                svc = p.find("service")
                services.append(DiscoveredService(
                    asset_value=addr,
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),
                    state=state,
                    product=(svc.get("product", "") if svc is not None else ""),
                    version=(svc.get("version", "") if svc is not None else ""),
                    confidence=(svc.get("conf", "") if svc is not None else ""),
                ))
                if svc is not None and (svc.get("name", "") in _WEBBISH or svc.get("tunnel") == "ssl"):
                    observations.append(DiscoveredObservation(
                        kind="TECH", key="web-port", value=f"{addr}:{p.get('portid')}",
                        source="nmap", asset_value=addr,
                    ))
                port_num = int(p.get("portid", "0")) or None
                for sc in p.findall("script"):
                    sid = sc.get("id", "")
                    if sid not in NSE_SCRIPTS:
                        continue
                    sout = sc.get("output", "")
                    observations.append(_script_observation(sid, sout, addr))
                    findings.extend(_findings_for_script(sid, sout, addr, port_num))
        for hs in host.findall("hostscript"):
            for sc in hs.findall("script"):
                sid = sc.get("id", "")
                if sid not in NSE_SCRIPTS:
                    continue
                sout = sc.get("output", "")
                observations.append(_script_observation(sid, sout, addr))
                findings.extend(_findings_for_script(sid, sout, addr, None))
        os_el = host.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch")[:2]:
                observations.append(DiscoveredObservation(
                    kind="OSINT", key="os-guess",
                    value=f"{m.get('name', '')} (accuracy {m.get('accuracy', '?')}%)",
                    source="nmap", asset_value=addr,
                ))
    return services, observations, findings, True
