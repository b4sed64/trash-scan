"""External OSINT lookups — Certificate Transparency logs (crt.sh) and WHOIS/RDAP
domain registration data. Lifts the "broader OSINT providers" line already sitting
in PRD §29's deferred backlog.

Unlike the rest of the tool bundle this is not a pinned CLI binary: it is a live
outbound call, at scan time, to a public third-party service, sending it the
target domain. That is a meaningfully different trust/privacy posture than a
checksum-pinned binary baked into the image, so it is **off by default**
(``TRASHSCAN_ENABLE_EXTERNAL_OSINT``) and documented in ``docs/CONFIGURATION.md``.
Domain targets only. Classified PASSIVE — it never sends anything to the target
itself, only to crt.sh/RDAP about the target's domain name.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from urllib.parse import quote

import httpx as http_client  # the Python HTTP client library — not a scanner CLI tool

from ..config import get_settings
from .base import (
    CLASSIFICATION_PASSIVE,
    STAGE_OSINT,
    DiscoveredAsset,
    DiscoveredFinding,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

_TIMEOUT_SECONDS = 8.0
_USER_AGENT = "TrashScan/1.0 (+authorized-recon-lookup)"
_EXPIRING_SOON_DAYS = 30

# Injectable HTTP fetcher so tests never touch the network — same pattern as
# services.scope_db.set_resolver. Takes a URL, returns parsed JSON or None.
_fetcher = None


def set_fetcher(func) -> None:
    global _fetcher
    _fetcher = func


def _get_json(url: str):
    if _fetcher is not None:
        return _fetcher(url)
    try:
        resp = http_client.get(url, timeout=_TIMEOUT_SECONDS, follow_redirects=True,
                               headers={"User-Agent": _USER_AGENT})
        resp.raise_for_status()
        return resp.json()
    except (http_client.HTTPError, ValueError):
        return None


def _rule_hash(rule_id: str, version: str = "v1") -> str:
    return hashlib.sha256(f"trashscan-internal-rule:{rule_id}:{version}".encode()).hexdigest()


def parse_crt_sh(raw, domain: str) -> list[str]:
    """crt.sh's ``?output=json`` is a list of certs with a newline-separated
    ``name_value`` field (SANs + CN). Keep only names that are the domain itself
    or a genuine subdomain of it."""
    if not isinstance(raw, list):
        return []
    suffix = "." + domain
    found: set[str] = set()
    for row in raw:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith(suffix)):
                found.add(name)
    return sorted(found)


def parse_rdap(raw) -> dict:
    """Extract the handful of RDAP fields used here; tolerant of schema gaps —
    RDAP responses vary noticeably between registries."""
    if not isinstance(raw, dict):
        return {}
    registrar = ""
    for entity in raw.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        for field in (entity.get("vcardArray") or [None, []])[1]:
            if isinstance(field, list) and len(field) > 3 and field[0] == "fn":
                registrar = str(field[3])
    events = {e.get("eventAction"): e.get("eventDate") for e in raw.get("events") or []
              if isinstance(e, dict)}
    nameservers = [ns.get("ldhName") for ns in raw.get("nameservers") or []
                   if isinstance(ns, dict) and ns.get("ldhName")]
    return {
        "registrar": registrar,
        "created": events.get("registration") or "",
        "expires": events.get("expiration") or "",
        "nameservers": nameservers,
    }


def registration_expiry_finding(rdap: dict, domain: str) -> DiscoveredFinding | None:
    expires = rdap.get("expires") or ""
    if not expires:
        return None
    try:
        expiry = dt.datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
    except ValueError:
        return None
    days_left = (expiry - dt.datetime.now(dt.timezone.utc)).days
    if days_left > _EXPIRING_SOON_DAYS:
        return None
    expired = days_left < 0
    rule_id = "osint-domain-registration-expired" if expired else "osint-domain-registration-expiring-soon"
    registrar = rdap.get("registrar") or "unknown registrar"
    return DiscoveredFinding(
        rule_id=rule_id, template_hash=_rule_hash(rule_id),
        severity="HIGH" if expired else "MEDIUM",
        name="Domain Registration Expired" if expired else "Domain Registration Expiring Soon",
        description="A lapsed domain registration can be re-registered by a third party, "
                    "hijacking the domain and everything hosted under it.",
        asset_value=domain, matched_at=f"rdap://{domain}", matcher_name="rdap",
        evidence_key=f"{rule_id}:{expires}",
        evidence_summary=f"{domain} ({registrar}) {'expired' if expired else 'expires'} {expires}",
        evidence={"registrar": registrar, "expires": expires, "days_left": days_left},
    )


class OsintAdapter:
    stage = STAGE_OSINT
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return "external-osint/1.0"

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="osint", tool_version=self.tool_version())
        if inp.target_kind != "DOMAIN":
            out.note = "external OSINT lookups only apply to domain targets"
            return out
        if not get_settings().enable_external_osint:
            out.note = "external OSINT lookups are disabled (TRASHSCAN_ENABLE_EXTERNAL_OSINT=false)"
            return out

        domain = inp.target_value
        encoded = quote(domain, safe="")
        out.args = [f"crt.sh?q=%25.{encoded}", f"rdap.org/domain/{encoded}"]
        notes: list[str] = []

        ct_raw = _get_json(f"https://crt.sh/?q=%25.{encoded}&output=json")
        if ct_raw is None:
            out.incomplete = True
            notes.append("crt.sh lookup failed or timed out")
        else:
            subdomains = parse_crt_sh(ct_raw, domain)
            for host in subdomains:
                out.assets.append(DiscoveredAsset(kind="HOSTNAME", value=host, source="crt.sh"))
            out.observations.append(DiscoveredObservation(
                kind="OSINT", key="ct-log-subdomains", value=str(len(subdomains)),
                source="crt.sh", asset_value=domain,
            ))

        rdap_raw = _get_json(f"https://rdap.org/domain/{encoded}")
        if rdap_raw is None:
            out.incomplete = True
            notes.append("RDAP lookup failed or timed out")
        else:
            rdap = parse_rdap(rdap_raw)
            for key in ("registrar", "created", "expires"):
                if rdap.get(key):
                    out.observations.append(DiscoveredObservation(
                        kind="OSINT", key=f"whois-{key}", value=str(rdap[key])[:200],
                        source="rdap", asset_value=domain,
                    ))
            if rdap.get("nameservers"):
                out.observations.append(DiscoveredObservation(
                    kind="OSINT", key="whois-nameservers", value=", ".join(rdap["nameservers"])[:400],
                    source="rdap", asset_value=domain,
                ))
            finding = registration_expiry_finding(rdap, domain)
            if finding:
                out.findings.append(finding)

        out.note = "; ".join(notes)
        out.ok = not out.incomplete or bool(out.assets or out.observations)
        return out
