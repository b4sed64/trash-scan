"""ProjectDiscovery httpx adapter — HTTP inspection (PRD §12.4).

Restrictions enforced here:
  * probe only the approved hosts/addresses passed in ``inp.hosts``;
  * bounded redirects (not followed by default — the Location header is captured
    and scope-checked by the caller), response size, retries, timeout, rate;
  * no arbitrary methods, paths, unsafe mode, or user-defined headers.
This is NOT the Python ``httpx`` client library.

``-tls-grab`` (already an approved capability — PRD §12.4 lists "TLS metadata")
returns the negotiated protocol, cipher and leaf certificate. ``tls_findings``
turns that into actionable, severity-ranked findings (expired/expiring
certificate, self-signed, hostname mismatch, deprecated protocol) instead of
leaving it as an inert observation. It is a pure function shared with the fake
adapter so both paths exercise identical rule logic.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_HTTPX,
    DiscoveredFinding,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_HTTPX_BIN", "httpx-pd")

# tlsx (which httpx's -tls-grab wraps) reports the negotiated version as one of
# these lowercase, dot-free strings. ssl30/tls10/tls11 are deprecated protocols;
# tls12/tls13 are fine.
_WEAK_TLS_VERSIONS = {"ssl30": "SSLv3", "tls10": "TLS 1.0", "tls11": "TLS 1.1"}
_EXPIRING_SOON_DAYS = 30


def _rule_hash(rule_id: str, version: str = "v1") -> str:
    """A stable stand-in for a Nuclei template hash, for findings this adapter
    derives itself rather than sourcing from a template."""
    return hashlib.sha256(f"trashscan-internal-rule:{rule_id}:{version}".encode()).hexdigest()


def _parse_cert_time(value: str) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def tls_findings(tls: dict, host: str) -> list[DiscoveredFinding]:
    """Derive TLS/certificate-posture findings from one ``-tls-grab`` result.

    Every field is read defensively — an older/newer httpx build, or a probe
    that never completed the handshake, may omit any of them.
    """
    if not tls:
        return []
    findings: list[DiscoveredFinding] = []
    port = None
    try:
        port = int(tls.get("port")) if tls.get("port") not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    subject = tls.get("subject_cn") or tls.get("subject_dn") or host
    issuer = tls.get("issuer_cn") or tls.get("issuer_dn") or "unknown"
    serial = str(tls.get("serial") or "")
    not_after = str(tls.get("not_after") or "")

    def _mk(rule_id: str, severity: str, name: str, description: str,
            evidence_key: str, evidence_summary: str, evidence: dict) -> DiscoveredFinding:
        return DiscoveredFinding(
            rule_id=rule_id, template_hash=_rule_hash(rule_id), severity=severity, name=name,
            description=description, asset_value=host, matched_at=f"tls://{host}:{port or 443}",
            matcher_name="tls-grab", port=port, protocol="tcp",
            evidence_key=evidence_key, evidence_summary=evidence_summary[:400], evidence=evidence,
        )

    if tls.get("expired"):
        findings.append(_mk(
            "tls-cert-expired", "HIGH", "TLS Certificate Expired",
            "The presented certificate's validity period has ended.",
            evidence_key=f"expired:{serial or subject}",
            evidence_summary=f"Certificate for {subject} (issuer {issuer}) expired {not_after}",
            evidence={"subject": subject, "issuer": issuer, "not_after": not_after},
        ))
    else:
        expiry = _parse_cert_time(not_after)
        if expiry is not None:
            now = dt.datetime.now(dt.timezone.utc)
            days_left = (expiry - now).days
            if 0 <= days_left <= _EXPIRING_SOON_DAYS:
                findings.append(_mk(
                    "tls-cert-expiring-soon", "MEDIUM", "TLS Certificate Expiring Soon",
                    f"The certificate expires within {_EXPIRING_SOON_DAYS} days.",
                    evidence_key=f"expiring:{serial or subject}",
                    evidence_summary=f"Certificate for {subject} expires {not_after} ({days_left}d left)",
                    evidence={"subject": subject, "not_after": not_after, "days_left": days_left},
                ))

    if tls.get("self_signed"):
        findings.append(_mk(
            "tls-self-signed", "LOW", "Self-Signed TLS Certificate",
            "The certificate is not issued by a recognized certificate authority.",
            evidence_key=f"self-signed:{serial or subject}",
            evidence_summary=f"{subject} presents a self-signed certificate",
            evidence={"subject": subject, "issuer": issuer},
        ))

    if tls.get("mismatched"):
        findings.append(_mk(
            "tls-hostname-mismatch", "MEDIUM", "TLS Certificate Hostname Mismatch",
            "The certificate's subject/SAN does not cover the host it was presented for.",
            evidence_key=f"mismatched:{serial or subject}",
            evidence_summary=f"Certificate subject {subject} does not match {host}",
            evidence={"subject": subject, "host": host, "subject_an": tls.get("subject_an") or []},
        ))

    version = str(tls.get("tls_version") or "").lower()
    if version in _WEAK_TLS_VERSIONS:
        label = _WEAK_TLS_VERSIONS[version]
        findings.append(_mk(
            "tls-deprecated-protocol", "HIGH" if version == "ssl30" else "MEDIUM",
            "Deprecated TLS Protocol Supported",
            f"The server negotiated {label}, which is deprecated and should be disabled.",
            evidence_key=f"weak-version:{version}",
            evidence_summary=f"{host} negotiated {label}",
            evidence={"tls_version": version, "cipher": tls.get("cipher") or ""},
        ))

    return findings


class HttpxAdapter:
    stage = STAGE_HTTPX
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN)

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="httpx", tool_version=self.tool_version())
        settings = get_settings()

        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to probe"
            return out

        infile = os.path.join(inp.result_dir, "httpx_input.txt")
        outfile = os.path.join(inp.result_dir, "httpx.jsonl")
        with open(infile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(probes) + "\n")

        rps = str(int(inp.limits.get("http_rps", settings.http_requests_per_second)))
        argv = [
            BIN, "-silent", "-json", "-no-color", "-disable-update-check",
            "-l", infile, "-o", outfile,
            "-status-code", "-title", "-tech-detect", "-content-type", "-web-server",
            "-location", "-tls-grab", "-response-time",
            "-timeout", "10", "-retries", "1",
            "-rate-limit", rps,
            "-response-size-to-read", str(int(settings.max_response_bytes)),
        ]
        if settings.httpx_follow_redirects:
            argv += ["-follow-redirects", "-max-redirects", str(int(settings.httpx_max_redirects))]
        out.args = argv[1:]

        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 900)),
                           cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"))
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "httpx binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        lines = _read_lines(outfile, res.stdout)
        out.observations, out.findings = _parse(lines, inp)
        out.ok = res.returncode == 0 or bool(out.observations)
        return out


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _in_scope(host: str, private_cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname — scope was already checked before the stage
    return any(addr in ipaddress.ip_network(c, strict=False) for c in private_cidrs)


def _parse(lines: list[str], inp: StageInput) -> tuple[list[DiscoveredObservation], list[DiscoveredFinding]]:
    observations: list[DiscoveredObservation] = []
    findings: list[DiscoveredFinding] = []
    private_cidrs = list(inp.options.get("_private_cidrs") or [])
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host") or row.get("input") or "")
        url = str(row.get("url") or "")
        anchor = host or url

        if row.get("status_code") is not None:
            observations.append(DiscoveredObservation(kind="HTTP_STATUS", key=url or host,
                                       value=str(row["status_code"]), source="httpx",
                                       asset_value=host or None))
        if row.get("title"):
            observations.append(DiscoveredObservation(kind="TITLE", key=anchor, value=str(row["title"])[:300],
                                       source="httpx", asset_value=host or None))
        if row.get("webserver"):
            observations.append(DiscoveredObservation(kind="HTTP_HEADER", key="Server",
                                       value=str(row["webserver"]), source="httpx",
                                       asset_value=host or None))
        if row.get("content_type"):
            observations.append(DiscoveredObservation(kind="HTTP_HEADER", key="Content-Type",
                                       value=str(row["content_type"]), source="httpx",
                                       asset_value=host or None))
        for tech in row.get("tech") or row.get("technologies") or []:
            observations.append(DiscoveredObservation(kind="TECH", key="tech", value=str(tech)[:80],
                                       source="httpx", asset_value=host or None))
        tls = row.get("tls") or {}
        if tls:
            subj = tls.get("subject_cn") or tls.get("subject_dn") or ""
            issuer = tls.get("issuer_cn") or tls.get("issuer_dn") or ""
            expiry = tls.get("not_after") or ""
            observations.append(DiscoveredObservation(kind="TLS", key="certificate",
                                       value=f"subject={subj}; issuer={issuer}; not_after={expiry}"[:400],
                                       source="httpx", asset_value=host or None))
            findings.extend(tls_findings(tls, host or anchor))
        loc = row.get("location")
        if loc:
            in_scope = _in_scope(str(loc).split("/")[2] if "//" in str(loc) else "", private_cidrs)
            observations.append(DiscoveredObservation(
                kind="HTTP_HEADER", key="Location",
                value=f"{loc}" + ("" if in_scope else "  [OUT OF APPROVED SCOPE — not followed]"),
                source="httpx", asset_value=host or None,
            ))
    return observations, findings
