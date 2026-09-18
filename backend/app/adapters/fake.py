"""Deterministic fake adapters.

Selected when ``TRASHSCAN_SCANNER_MODE=fake`` (and always in tests). Output is a
pure function of the target so parsers, normalization and the execution
lifecycle can be exercised without any network traffic.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from urllib.parse import urlparse

from .base import (
    CLASSIFICATION_ACTIVE,
    CLASSIFICATION_PASSIVE,
    STAGE_DNSX,
    STAGE_HTTPX,
    STAGE_KATANA,
    STAGE_NMAP,
    STAGE_NUCLEI,
    STAGE_OSINT,
    STAGE_SUBFINDER,
    DiscoveredAsset,
    DiscoveredFinding,
    DiscoveredObservation,
    DiscoveredService,
    StageInput,
    StageOutput,
)
from .dnsx import dns_posture_findings
from .httpx import tls_findings
from .osint import registration_expiry_finding

FAKE_VERSION = "fake/2.0.0"


def _octet(seed: str, salt: str) -> int:
    return hashlib.sha256(f"{seed}:{salt}".encode()).digest()[0] % 254 + 1


def _probe_host(probe: str) -> str:
    """A probe is usually a bare ``ip[:port]`` (seeded by nmap), but katana can
    add full URLs (``http://ip:port/path``) to the same pool — extract the host
    correctly either way, the same as a real httpx/nuclei invocation would."""
    if "://" in probe:
        return urlparse(probe).hostname or probe
    return probe.split(":")[0]


class FakeSubfinderAdapter:
    stage = STAGE_SUBFINDER
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="subfinder", tool_version=FAKE_VERSION,
                          args=["-fake", "-d", inp.target_value])
        if inp.target_kind != "DOMAIN":
            out.note = "subfinder only applies to domain targets"
            return out
        for label in ("www", "api", "vpn", "mail"):
            out.assets.append(
                DiscoveredAsset(kind="HOSTNAME", value=f"{label}.{inp.target_value}",
                                source="subfinder")
            )
        # A deliberately out-of-scope discovery to exercise the unapproved path.
        out.assets.append(
            DiscoveredAsset(kind="HOSTNAME", value=f"cdn.{inp.target_value}.example.net",
                            source="subfinder")
        )
        return out


class FakeDnsxAdapter:
    stage = STAGE_DNSX
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="dnsx", tool_version=FAKE_VERSION,
                          args=["-fake", "-a", "-cname"])
        hosts = list(inp.hosts)
        if inp.target_kind == "DOMAIN":
            hosts.append(inp.target_value)
        elif inp.target_kind == "IPV4":
            out.assets.append(DiscoveredAsset(kind="IP", value=inp.target_value, source="dnsx"))
            out.observations.append(
                DiscoveredObservation(kind="DNS_RECORD", key="PTR",
                                      value=f"host-{inp.target_value.replace('.', '-')}.lab.internal",
                                      source="dnsx", asset_value=inp.target_value)
            )
        for host in sorted(set(h for h in hosts if "." in h and not _is_ipish(h))):
            # Land inside a typical lab /16 so scope classification is exercised.
            ip = f"10.10.{_octet(host, 'a')}.{_octet(host, 'b')}"
            out.assets.append(DiscoveredAsset(kind="IP", value=ip, source="dnsx"))
            out.observations.append(
                DiscoveredObservation(kind="DNS_RECORD", key="A", value=ip, source="dnsx",
                                      asset_value=host)
            )
            out.observations.append(
                DiscoveredObservation(kind="DNS_RECORD", key="NS", value="ns1.lab.internal",
                                      source="dnsx", asset_value=host)
            )
        if inp.target_kind == "DOMAIN":
            # No synthetic SPF/DMARC/CAA records are emitted above, so this
            # deterministically surfaces the "missing record" findings offline —
            # the same rule logic the real adapter uses on real DNS answers.
            out.findings = dns_posture_findings(out.observations, inp.target_value)
        return out


class FakeNmapAdapter:
    stage = STAGE_NMAP
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="nmap", tool_version=FAKE_VERSION,
                          args=["-fake", "-sT", "-sV"])
        ips = sorted({h for h in inp.hosts if _is_ipish(h)})
        if not ips:
            out.note = "no resolved in-scope IPs to scan"
            return out
        for ip in ips:
            for port, product in ((22, "OpenSSH"), (80, "nginx"), (443, "nginx")):
                if (_octet(ip, str(port)) % 4) == 0 and port != 22:
                    continue
                out.services.append(DiscoveredService(
                    asset_value=ip, port=port, protocol="tcp", state="open",
                    product=product, version="1.0", confidence="10",
                ))
                if port in (80, 443):
                    out.observations.append(DiscoveredObservation(
                        kind="TECH", key="web-port", value=f"{ip}:{port}", source="nmap",
                        asset_value=ip,
                    ))
        if inp.profile == "STANDARD_ACTIVE":
            out.observations.append(DiscoveredObservation(
                kind="OSINT", key="os-guess", value="Linux 5.x (accuracy 90%)", source="nmap",
                asset_value=ips[0],
            ))
        return out


class FakeHttpxAdapter:
    stage = STAGE_HTTPX
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="httpx", tool_version=FAKE_VERSION,
                          args=["-fake", "-status-code", "-title"])
        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to probe"
            return out
        for probe in probes:
            host = _probe_host(probe)
            out.observations.append(DiscoveredObservation(
                kind="HTTP_STATUS", key=f"http://{probe}", value="200", source="httpx",
                asset_value=host,
            ))
            out.observations.append(DiscoveredObservation(
                kind="TITLE", key=probe, value="Lab service", source="httpx",
                asset_value=host,
            ))
            out.observations.append(DiscoveredObservation(
                kind="HTTP_HEADER", key="Server", value="nginx/1.25.0", source="httpx",
                asset_value=host,
            ))
            tls = {
                "port": "443", "tls_version": "tls12", "cipher": "TLS_AES_128_GCM_SHA256",
                "subject_cn": host, "issuer_cn": "Lab Internal CA",
                "not_after": "2099-01-01T00:00:00Z", "serial": f"fake-{host}",
                "expired": False, "self_signed": False, "mismatched": False,
            }
            if _octet(host, "tls-self-signed") % 3 == 0:
                tls["self_signed"] = True
                tls["issuer_cn"] = host
            if _octet(host, "tls-weak-version") % 5 == 0:
                tls["tls_version"] = "tls10"
            if _octet(host, "tls-expiring") % 7 == 0:
                tls["not_after"] = "2026-01-01T00:00:00Z"  # exercised only near that date
            out.observations.append(DiscoveredObservation(
                kind="TLS", key="certificate",
                value=f"subject={tls['subject_cn']}; issuer={tls['issuer_cn']}; not_after={tls['not_after']}",
                source="httpx", asset_value=host,
            ))
            out.findings.extend(tls_findings(tls, host))
        return out


class FakeKatanaAdapter:
    stage = STAGE_KATANA
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="katana", tool_version=FAKE_VERSION,
                          args=["-fake", "-depth", "1", "-js-crawl"])
        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to crawl"
            return out
        for probe in probes:
            host = probe.split(":")[0]
            for path in ("/login", "/api/v1/status"):
                out.observations.append(DiscoveredObservation(
                    kind="TECH", key="endpoint", value=f"http://{probe}{path}",
                    source="katana", asset_value=host,
                ))
        return out


class FakeNucleiAdapter:
    stage = STAGE_NUCLEI
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="nuclei", tool_version=FAKE_VERSION,
                          args=["-fake", "-t", "templates/nuclei"])
        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to probe"
            return out
        # A deterministic mix so comparison logic can be demonstrated.
        drop = str(inp.options.get("_fake_findings_drop") or "")
        for probe in probes:
            host = _probe_host(probe)
            probe_url = probe if "://" in probe else f"http://{probe}/"
            catalogue = [
                ("trashscan-missing-security-headers", "LOW", "Missing HTTP Security Headers",
                 "x-frame-options,content-security-policy"),
                ("trashscan-server-version-disclosure", "LOW", "Server Version Disclosure",
                 "nginx/1.25.0"),
                ("trashscan-nginx-default-page", "INFO", "Nginx Default Welcome Page", "body"),
            ]
            if _octet(host, "git") % 2 == 1:
                catalogue.append(
                    ("trashscan-git-config-exposure", "MEDIUM", "Exposed .git/config",
                     "[core] repositoryformatversion")
                )
            if inp.profile == "STANDARD_ACTIVE":
                # Broader profile surfaces one more indicator — makes NEW vs
                # NOT_OBSERVED visible when alternating profiles in a demo.
                catalogue.append(
                    ("trashscan-directory-listing", "LOW", "Directory Listing Enabled",
                     "Index of /")
                )
            for rule_id, sev, name, ev in catalogue:
                if rule_id == drop:
                    continue
                out.findings.append(DiscoveredFinding(
                    rule_id=rule_id, template_hash=f"fake-{rule_id}", severity=sev, name=name,
                    description=name, asset_value=host, matched_at=probe_url,
                    matcher_name="word", port=80, protocol="tcp",
                    evidence_key=f"{rule_id}|word|{ev}", evidence_summary=f"{name} at {probe_url}",
                    evidence={"extracted": [ev]},
                ))
        return out


class FakeOsintAdapter:
    stage = STAGE_OSINT
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return FAKE_VERSION

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="osint", tool_version=FAKE_VERSION,
                          args=["-fake", "crt.sh", "rdap.org"])
        if inp.target_kind != "DOMAIN":
            out.note = "external OSINT lookups only apply to domain targets"
            return out
        # Deterministic stand-in for a live crt.sh/RDAP lookup. Fake mode never
        # touches the network regardless of TRASHSCAN_ENABLE_EXTERNAL_OSINT, so
        # this always runs — the same reason every other fake adapter ignores the
        # flags that gate its real counterpart's capabilities.
        domain = inp.target_value
        out.assets.append(DiscoveredAsset(kind="HOSTNAME", value=f"legacy.{domain}", source="crt.sh"))
        out.observations.append(DiscoveredObservation(
            kind="OSINT", key="ct-log-subdomains", value="1", source="crt.sh", asset_value=domain,
        ))
        days_offset = _octet(domain, "whois-expiry") % 60 - 10  # -10..49 days: varies by target
        expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days_offset))
        rdap = {
            "registrar": "Fake Registrar, Inc.",
            "created": "2015-01-01T00:00:00Z",
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nameservers": ["ns1.lab.internal", "ns2.lab.internal"],
        }
        for key in ("registrar", "created", "expires"):
            out.observations.append(DiscoveredObservation(
                kind="OSINT", key=f"whois-{key}", value=str(rdap[key]),
                source="rdap", asset_value=domain,
            ))
        out.observations.append(DiscoveredObservation(
            kind="OSINT", key="whois-nameservers", value=", ".join(rdap["nameservers"]),
            source="rdap", asset_value=domain,
        ))
        finding = registration_expiry_finding(rdap, domain)
        if finding:
            out.findings.append(finding)
        return out


def _is_ipish(v: str) -> bool:
    v = v.split(":")[0]
    return all(part.isdigit() for part in v.split(".") if part) and v.count(".") == 3
