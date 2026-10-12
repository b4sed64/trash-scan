"""Mode-specific capability support matrix (PRD v2 §24 / Phase 23).

The single authoritative statement of what this build can and cannot do. Every
field is derived from configuration (feature flags) and fixed build facts — never
from a scan/proof/session *result*. This is the invariant the release acceptance
depends on: **no mode is ever reported as enabled because a (possibly fake)
result looked successful.** ``enabled`` mirrors a flag; ``backing`` states whether
a real implementation is wired in this build; ``real_lab_gate`` names the
authorized-lab demonstration still required before a real mode may ship on.
"""
from __future__ import annotations

from ..config import Settings, get_settings

# backing kinds
REAL = "real"          # a real implementation is wired and used when enabled
FAKE = "fake"          # only a fake/simulated implementation exists in this build
OFFLINE = "offline"    # analytical only; never contacts a target or executes


def _capabilities(s: Settings) -> list[dict]:
    """Capability rows. ``enabled`` comes ONLY from the flag; ``backing`` is a
    fixed fact about this build; neither is influenced by any result."""
    return [
        {
            "key": "scanning",
            "title": "Authorized Reconnaissance Scanning",
            "flag": None,
            "enabled": True,
            # Scanning has a real adapter, but the data is synthetic in fake mode.
            "backing": REAL if s.scanner_mode == "real" else FAKE,
            "real_lab_gate": "Authorized scan of the supported lab target with "
                             "real adapters; verify coverage and patched negatives.",
        },
        {
            "key": "exploitability_assessment",
            "title": "Exploitability Assessment",
            "flag": "enable_exploitability_assessment",
            "enabled": s.enable_exploitability_assessment,
            "backing": OFFLINE,
            "real_lab_gate": "None — offline analytical issue→module assessment; "
                             "no target contact, no execution.",
        },
        {
            "key": "lab_checks",
            "title": "Active Lab Prerequisite Checks",
            "flag": "enable_lab_checks",
            "enabled": s.enable_lab_checks,
            "backing": FAKE,
            "real_lab_gate": "Active prerequisite checks against a proven-isolated "
                             "lab surface, with their own plan/attestation/approval.",
        },
        {
            "key": "lab_proof",
            "title": "One-Shot Proof / Exploitation",
            "flag": "enable_lab_proof",
            "enabled": s.enable_lab_proof,
            # A real Metasploit backend exists (Phase 24); it is live only when
            # framework_mode=real, otherwise the fake drives the lifecycle.
            "backing": REAL if s.framework_mode == "real" else FAKE,
            "framework_mode": s.framework_mode,
            "real_lab_gate": "Controlled one-shot proof/exploit against a "
                             "registered, isolated lab fixture with recovery "
                             "verified; msfrpcd reachable for framework_mode=real.",
        },
        {
            "key": "guided_sessions",
            "title": "Verified Sessions & Guided Actions",
            "flag": "enable_guided_sessions",
            "enabled": s.enable_guided_sessions,
            "backing": FAKE,
            "real_lab_gate": "Internal listener on a proven-isolated topology, a "
                             "verified session and predefined guided actions.",
        },
        {
            "key": "lab_terminal",
            "title": "Administrator Target-Session Terminal",
            "flag": "enable_lab_terminal",
            "enabled": s.enable_lab_terminal,
            "backing": FAKE,
            "real_lab_gate": "A real command-output channel on an admitted, "
                             "verified session within a granted time.",
        },
        {
            "key": "external_osint",
            "title": "External OSINT Enrichment",
            "flag": "enable_external_osint",
            "enabled": s.enable_external_osint,
            "backing": REAL,
            "real_lab_gate": "None — opt-in external lookups; off by default.",
        },
    ]


def data_provenance(s: Settings | None = None) -> dict:
    """Describe where scan data comes from, so fake/demo data is never mistaken
    for real findings. ``synthetic`` is true whenever the scanner is not in real
    mode."""
    s = s or get_settings()
    synthetic = s.scanner_mode != "real"
    return {
        "scanner_mode": s.scanner_mode,
        "synthetic": synthetic,
        "note": ("Scan data is SYNTHETIC (fake adapters) and must not be read as "
                 "real findings." if synthetic else
                 "Scan data is from real adapters."),
    }


def support_matrix(s: Settings | None = None) -> dict:
    """The published, authoritative capability support matrix.

    Everything here is a function of configuration + build facts. A fake result
    can never make a disabled mode appear enabled, nor a fake-backed mode appear
    real."""
    s = s or get_settings()
    caps = _capabilities(s)
    return {
        "release": "1.0.0",
        "framework_mode": s.framework_mode,
        "data_provenance": data_provenance(s),
        "capabilities": caps,
        "disabled_optional_modes": [c["key"] for c in caps if not c["enabled"]],
        "fake_backed_modes": [c["key"] for c in caps if c["backing"] == FAKE],
        "notes": [
            "A feature flag alone never approves a job; gated modes also require "
            "their own plan/attestation/approval and lab/recovery gates.",
            "'enabled' reflects configuration only; it is never set by a result.",
            "Fake-backed modes have no real implementation in this build and "
            "cannot contact or affect a real target.",
            "No claim of broad vulnerability absence or universal exploitability "
            "is made.",
        ],
    }
