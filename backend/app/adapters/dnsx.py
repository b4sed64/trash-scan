"""dnsx adapter — DNS resolution and record retrieval (PRD §12.3).

Wordlist and brute-force modes are never enabled (no ``-w``/``-d`` dictionary
input). Rate limits and bounded retries always apply. A DNS response is never
converted into active scope by this adapter.

TXT and CAA records are already an approved dnsx responsibility. ``dns_posture_findings``
interprets the ones that carry an email/certificate-authority policy (SPF, DMARC,
CAA) into actionable findings instead of leaving them as inert raw-record
observations — passive, no approval needed, since it is pure DNS lookup.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os

from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_PASSIVE,
    STAGE_DNSX,
    DiscoveredAsset,
    DiscoveredFinding,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_DNSX_BIN", "dnsx")

_RECORD_FLAGS = ["-a", "-aaaa", "-cname", "-ns", "-txt", "-mx", "-soa", "-caa"]
_DMARC_PREFIX = "_dmarc."


def _rule_hash(rule_id: str, version: str = "v1") -> str:
    return hashlib.sha256(f"trashscan-internal-rule:{rule_id}:{version}".encode()).hexdigest()


def _mk(rule_id: str, severity: str, name: str, description: str, asset: str,
        evidence_key: str, evidence_summary: str, evidence: dict) -> DiscoveredFinding:
    return DiscoveredFinding(
        rule_id=rule_id, template_hash=_rule_hash(rule_id), severity=severity, name=name,
        description=description, asset_value=asset, matched_at=f"dns://{asset}",
        matcher_name="dns-record", port=None, protocol="tcp",
        evidence_key=evidence_key, evidence_summary=evidence_summary[:400], evidence=evidence,
    )


def dns_posture_findings(observations: list[DiscoveredObservation], domain: str) -> list[DiscoveredFinding]:
    """Interpret the SPF/DMARC/CAA posture of ``domain`` from already-collected
    TXT/CAA observations. Domain-only — SPF/DMARC/CAA are DNS-mail/CA concepts
    that don't apply to a bare IP or CIDR target."""
    txt_apex = [o.value for o in observations
                if o.kind == "DNS_RECORD" and o.key == "TXT" and o.asset_value == domain]
    txt_dmarc = [o.value for o in observations
                 if o.kind == "DNS_RECORD" and o.key == "TXT" and o.asset_value == _DMARC_PREFIX + domain]
    caa_apex = [o.value for o in observations
                if o.kind == "DNS_RECORD" and o.key == "CAA" and o.asset_value == domain]

    findings: list[DiscoveredFinding] = []

    spf = next((t for t in txt_apex if t.lower().startswith("v=spf1")), None)
    if spf is None:
        findings.append(_mk(
            "dns-spf-missing", "MEDIUM", "Missing SPF Record",
            "No SPF TXT record was found; mail sent as this domain cannot be authenticated by SPF.",
            domain, evidence_key="spf-missing",
            evidence_summary=f"{domain} has no v=spf1 TXT record",
            evidence={"txt_records": txt_apex},
        ))
    elif "+all" in spf.lower():
        findings.append(_mk(
            "dns-spf-permissive", "MEDIUM", "Permissive SPF Record (+all)",
            "The SPF record ends in '+all', which authorizes any host to send mail as this domain.",
            domain, evidence_key="spf-permissive",
            evidence_summary=f"{domain} SPF record: {spf}",
            evidence={"spf": spf},
        ))

    dmarc = next((t for t in txt_dmarc if t.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        findings.append(_mk(
            "dns-dmarc-missing", "MEDIUM", "Missing DMARC Record",
            "No DMARC TXT record was found at _dmarc.<domain>; spoofed mail is not policed.",
            domain, evidence_key="dmarc-missing",
            evidence_summary=f"_dmarc.{domain} has no v=DMARC1 TXT record",
            evidence={"txt_records": txt_dmarc},
        ))
    elif "p=none" in dmarc.lower():
        findings.append(_mk(
            "dns-dmarc-policy-none", "LOW", "DMARC Policy Set To Monitor Only (p=none)",
            "The DMARC policy is 'none', so failing messages are reported but not rejected/quarantined.",
            domain, evidence_key="dmarc-policy-none",
            evidence_summary=f"_dmarc.{domain} DMARC record: {dmarc}",
            evidence={"dmarc": dmarc},
        ))

    if not caa_apex:
        findings.append(_mk(
            "dns-caa-missing", "LOW", "No CAA Record (Any CA May Issue Certificates)",
            "No CAA record restricts which certificate authorities may issue for this domain.",
            domain, evidence_key="caa-missing",
            evidence_summary=f"{domain} has no CAA record",
            evidence={},
        ))

    return findings


class DnsxAdapter:
    stage = STAGE_DNSX
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return _tool_version(BIN)

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="dnsx",
                          tool_version=self.tool_version())

        hostnames = sorted({h.lower().rstrip(".") for h in inp.hosts if _is_hostname(h)})
        ips = sorted({h for h in inp.hosts if _is_ip(h)})
        if inp.target_kind == "DOMAIN":
            # Also resolve the DMARC subdomain so dns_posture_findings can see it;
            # SPF/CAA live on the apex record already being queried below.
            hostnames = sorted(set(hostnames) | {inp.target_value, _DMARC_PREFIX + inp.target_value})

        if not hostnames and not ips:
            out.note = "no hostnames or IPs to resolve"
            return out

        outfile = os.path.join(inp.result_dir, "dnsx.jsonl")
        infile = os.path.join(inp.result_dir, "dnsx_input.txt")
        with open(infile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(hostnames + ips) + "\n")

        rate = str(int(inp.limits.get("dns_qps", 20)))
        argv = [
            BIN, "-silent", "-json", "-resp",
            "-l", infile,
            "-o", outfile,
            "-rate-limit", rate,
            "-retry", "2",
            "-t", "50",
            "-disable-update-check",
            "-no-color",
            *_RECORD_FLAGS,
        ]
        if ips:
            argv.append("-ptr")
        for resolver in inp.resolvers:
            argv += ["-r", resolver]
        out.args = argv[1:]

        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 600)),
                           cwd=inp.result_dir)
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "dnsx binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        assets, observations = _parse(_read_lines(outfile, res.stdout))
        out.assets = assets
        out.observations = observations
        if inp.target_kind == "DOMAIN":
            out.findings = dns_posture_findings(observations, inp.target_value)
        out.ok = res.returncode == 0 or bool(assets or observations)
        return out


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _is_hostname(v: str) -> bool:
    return not _is_ip(v) and "." in v and " " not in v


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _parse(lines: list[str]) -> tuple[list[DiscoveredAsset], list[DiscoveredObservation]]:
    assets: dict[tuple[str, str], DiscoveredAsset] = {}
    obs: dict[tuple[str, str, str], DiscoveredObservation] = {}

    def add_asset(kind: str, value: str) -> None:
        assets.setdefault((kind, value), DiscoveredAsset(kind=kind, value=value, source="dnsx"))

    def add_obs(kind: str, key: str, value: str, host: str | None) -> None:
        obs.setdefault((kind, key, value),
                       DiscoveredObservation(kind=kind, key=key, value=value,
                                             source="dnsx", asset_value=host))

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        if host and _is_hostname(host):
            add_asset("HOSTNAME", host)
        for ip in _as_list(row.get("a")):
            add_asset("IP", ip)
            add_obs("DNS_RECORD", "A", ip, host)
        for ip in _as_list(row.get("aaaa")):
            add_obs("DNS_RECORD", "AAAA", ip, host)
        for cname in _as_list(row.get("cname")):
            add_obs("DNS_RECORD", "CNAME", cname, host)
        for rec_type in ("ns", "mx", "txt", "soa", "caa", "ptr"):
            for val in _as_list(row.get(rec_type)):
                add_obs("DNS_RECORD", rec_type.upper(), str(val)[:512], host)

    return list(assets.values()), list(obs.values())


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip().rstrip(".") for v in value if str(v).strip()]
    return [str(value).strip().rstrip(".")]
