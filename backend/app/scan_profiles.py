"""Scan-profile definitions and the UI-option -> tool-argument allowlist.

Users never choose raw flags (PRD §13, §22, §31). A profile maps to a fixed set
of stages, and each stage's arguments are assembled from product-defined options
only.
"""
from __future__ import annotations

from dataclasses import dataclass

from .adapters.base import (
    STAGE_DNSX,
    STAGE_HTTPX,
    STAGE_NMAP,
    STAGE_NUCLEI,
    STAGE_SUBFINDER,
)

PASSIVE = "PASSIVE"
SAFE_ACTIVE = "SAFE_ACTIVE"
STANDARD_ACTIVE = "STANDARD_ACTIVE"

ACTIVE_PROFILES = (SAFE_ACTIVE, STANDARD_ACTIVE)
ALL_PROFILES = (PASSIVE, SAFE_ACTIVE, STANDARD_ACTIVE)


@dataclass(frozen=True)
class Profile:
    name: str
    classification: str
    stages: tuple[str, ...]
    # Nmap capabilities permitted for this profile.
    nmap_service_detection: bool
    nmap_syn: bool          # requires raw packet capability
    nmap_os_detection: bool  # requires raw packet capability
    description: str


PROFILES: dict[str, Profile] = {
    PASSIVE: Profile(
        name=PASSIVE, classification="PASSIVE",
        stages=(STAGE_SUBFINDER, STAGE_DNSX),
        nmap_service_detection=False, nmap_syn=False, nmap_os_detection=False,
        description="Public OSINT, passive subdomains, DNS resolution. No approval required.",
    ),
    SAFE_ACTIVE: Profile(
        name=SAFE_ACTIVE, classification="ACTIVE",
        stages=(STAGE_DNSX, STAGE_NMAP, STAGE_HTTPX, STAGE_NUCLEI),
        nmap_service_detection=True, nmap_syn=False, nmap_os_detection=False,
        description="TCP connect scan of common ports, light service metadata, HTTP inspection, "
                    "reviewed low-impact Nuclei templates.",
    ),
    STANDARD_ACTIVE: Profile(
        name=STANDARD_ACTIVE, classification="ACTIVE",
        stages=(STAGE_DNSX, STAGE_NMAP, STAGE_HTTPX, STAGE_NUCLEI),
        nmap_service_detection=True, nmap_syn=True, nmap_os_detection=True,
        description=(
            "Broader TCP port set, service/version detection, HTTP inspection. "
            "SYN scan and OS detection only where raw-packet capability is available."
        ),
    ),
}


def profile_for(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown profile {name!r}") from exc


# Rate-choice allowlist: label -> per-second value (never a raw --rate flag).
RATE_CHOICES = {"CONSERVATIVE": 5, "MODERATE": 10}


def resolve_rate(choice: str | None, default: int) -> int:
    return RATE_CHOICES.get((choice or "").upper(), default)


# Predefined port selections offered in the UI. "" means "use the profile default
# from configuration". Users may also supply a custom list/ranges.
PORT_PRESETS: dict[str, str] = {
    "PROFILE_DEFAULT": "",
    "WEB": "80,443,8080,8443,8000,8888",
    "COMMON": "21,22,23,25,53,80,110,139,143,389,443,445,465,587,993,995,1433,1521,"
              "3306,3389,5432,5900,6379,8080,8443,9200,11211,27017",
    "TOP_1024": "1-1024",
}

MAX_SCAN_PORTS = 6000


class PortSpecError(ValueError):
    pass


def parse_port_spec(spec: str | None) -> str | None:
    """Validate and canonicalise a user-supplied port spec.

    Accepts comma-separated ports and ``a-b`` ranges only. Returns ``None`` for an
    empty spec (meaning: fall back to the profile default). Raises
    :class:`PortSpecError` on anything malformed or larger than ``MAX_SCAN_PORTS``.
    """
    if spec is None:
        return None
    spec = spec.replace(" ", "").strip(",")
    if not spec:
        return None
    total = 0
    parts: list[str] = []
    for token in spec.split(","):
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as exc:
                raise PortSpecError(f"invalid port range: {token!r}") from exc
            if not (1 <= lo <= hi <= 65535):
                raise PortSpecError(f"port range out of bounds: {token!r}")
            total += hi - lo + 1
            parts.append(f"{lo}-{hi}")
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise PortSpecError(f"invalid port: {token!r}") from exc
            if not (1 <= port <= 65535):
                raise PortSpecError(f"port out of bounds: {token!r}")
            total += 1
            parts.append(str(port))
        if total > MAX_SCAN_PORTS:
            raise PortSpecError(f"too many ports requested (limit {MAX_SCAN_PORTS})")
    if not parts:
        return None
    return ",".join(parts)


def resolve_ports(preset: str | None, custom: str | None) -> str | None:
    if preset and preset.upper() in PORT_PRESETS and preset.upper() != "CUSTOM":
        return parse_port_spec(PORT_PRESETS[preset.upper()] or None)
    return parse_port_spec(custom)
