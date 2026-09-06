"""Common scanner adapter interface (PRD §13, §26, §31).

Every adapter:
  * receives a typed :class:`StageInput` — never an ORM object;
  * builds an operating-system argument *array* from a fixed allowlist and never
    a shell string;
  * treats all tool output as untrusted;
  * returns a typed :class:`StageOutput`.

Phase 2 ships ``subfinder`` and ``dnsx`` (passive) plus deterministic fakes.
Phase 3 adds ``nmap`` and ``httpx`` behind the same protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

PARSER_VERSION = "2"

# Stage names --------------------------------------------------------------
STAGE_SUBFINDER = "subfinder"
STAGE_DNSX = "dnsx"
STAGE_NMAP = "nmap"
STAGE_HTTPX = "httpx"
STAGE_NUCLEI = "nuclei"

CLASSIFICATION_PASSIVE = "PASSIVE"
CLASSIFICATION_ACTIVE = "ACTIVE"


@dataclass(frozen=True)
class StageInput:
    stage: str
    target_kind: str          # IPV4 | CIDR | DOMAIN
    target_value: str         # canonical
    profile: str              # PASSIVE | SAFE_ACTIVE | STANDARD_ACTIVE
    hosts: list[str] = field(default_factory=list)   # explicit hosts/IPs to act on
    options: dict = field(default_factory=dict)      # resolved from the UI allowlist
    limits: dict = field(default_factory=dict)
    result_dir: str = ""
    resolvers: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiscoveredAsset:
    kind: str                 # IP | HOSTNAME
    value: str
    source: str


@dataclass(frozen=True)
class DiscoveredObservation:
    kind: str                 # DNS_RECORD | HTTP_HEADER | HTTP_STATUS | TLS | TECH | TITLE | OSINT
    key: str
    value: str
    source: str
    asset_value: str | None = None


@dataclass(frozen=True)
class DiscoveredFinding:
    rule_id: str
    template_hash: str
    severity: str            # INFO | LOW | MEDIUM | HIGH | CRITICAL
    name: str
    description: str
    asset_value: str
    matched_at: str
    matcher_name: str = ""
    port: int | None = None
    protocol: str = "tcp"
    # A stable subset of the evidence used for the fingerprint (no timestamps or
    # random response values) plus a bounded human-readable summary.
    evidence_key: str = ""
    evidence_summary: str = ""
    evidence: dict | None = None


@dataclass(frozen=True)
class DiscoveredService:
    asset_value: str
    port: int
    protocol: str             # tcp
    state: str                # open | closed | filtered
    product: str = ""
    version: str = ""
    confidence: str = ""


@dataclass
class StageOutput:
    stage: str
    ok: bool
    tool: str
    tool_version: str
    args: list[str] = field(default_factory=list)
    assets: list[DiscoveredAsset] = field(default_factory=list)
    observations: list[DiscoveredObservation] = field(default_factory=list)
    services: list[DiscoveredService] = field(default_factory=list)
    findings: list["DiscoveredFinding"] = field(default_factory=list)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    raw_path: str | None = None
    duration_ms: int = 0
    incomplete: bool = False
    note: str = ""


class ScannerAdapter(Protocol):
    stage: str
    classification: str

    def tool_version(self) -> str: ...

    def run(self, inp: StageInput) -> StageOutput: ...
