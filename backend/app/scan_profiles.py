"""Scan-profile definitions and the UI-option -> tool-argument allowlist.

Users never choose raw flags (PRD §13, §22, §31). A profile maps to a fixed set
of stages, and each stage's arguments are assembled from product-defined options
only.
"""
from __future__ import annotations

from dataclasses import dataclass

from .adapters.base import STAGE_DNSX, STAGE_HTTPX, STAGE_NMAP, STAGE_SUBFINDER

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
        stages=(STAGE_DNSX, STAGE_NMAP, STAGE_HTTPX),
        nmap_service_detection=True, nmap_syn=False, nmap_os_detection=False,
        description="TCP connect scan of common ports, light service metadata, HTTP inspection.",
    ),
    STANDARD_ACTIVE: Profile(
        name=STANDARD_ACTIVE, classification="ACTIVE",
        stages=(STAGE_DNSX, STAGE_NMAP, STAGE_HTTPX),
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
