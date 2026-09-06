"""Common scanner adapter interface (PRD 26 / 31).

Adapters receive typed input/output models only — never ORM instances — and
never build shell command strings. Phase 1 ships the fake adapter; real tool
adapters (Nmap, Subfinder, dnsx, httpx, Nuclei) implement the same protocol in
later phases.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ScanInput:
    target_kind: str  # IPV4 | CIDR | DOMAIN
    target_value: str  # canonical value
    profile: str  # PASSIVE | SAFE_ACTIVE | STANDARD_ACTIVE
    # A fixed allowlist of options resolved from UI choices, never raw flags.
    options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class DiscoveredAsset:
    kind: str  # IP | HOSTNAME
    value: str
    source: str


@dataclass(frozen=True)
class AdapterResult:
    ok: bool
    tool: str
    tool_version: str
    assets: list[DiscoveredAsset] = field(default_factory=list)
    stderr: str = ""
    incomplete_stages: list[str] = field(default_factory=list)


class ScannerAdapter(Protocol):
    name: str
    classification: str  # PASSIVE | ACTIVE

    def run(self, scan: ScanInput) -> AdapterResult: ...
