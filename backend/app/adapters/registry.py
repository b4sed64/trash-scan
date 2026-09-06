"""Adapter registry — resolves a stage name to a concrete adapter.

The scanner mode (``real`` vs ``fake``) is chosen once from configuration. New
tools must be added here *and* to the option allowlist with tests (PRD §31).
"""
from __future__ import annotations

from ..config import get_settings
from .base import (
    STAGE_DNSX,
    STAGE_HTTPX,
    STAGE_NMAP,
    STAGE_NUCLEI,
    STAGE_SUBFINDER,
    ScannerAdapter,
)
from .dnsx import DnsxAdapter
from .fake import (
    FakeDnsxAdapter,
    FakeHttpxAdapter,
    FakeNmapAdapter,
    FakeNucleiAdapter,
    FakeSubfinderAdapter,
)
from .httpx import HttpxAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .subfinder import SubfinderAdapter

_REAL = {
    STAGE_SUBFINDER: SubfinderAdapter,
    STAGE_DNSX: DnsxAdapter,
    STAGE_NMAP: NmapAdapter,
    STAGE_HTTPX: HttpxAdapter,
    STAGE_NUCLEI: NucleiAdapter,
}
_FAKE = {
    STAGE_SUBFINDER: FakeSubfinderAdapter,
    STAGE_DNSX: FakeDnsxAdapter,
    STAGE_NMAP: FakeNmapAdapter,
    STAGE_HTTPX: FakeHttpxAdapter,
    STAGE_NUCLEI: FakeNucleiAdapter,
}


def get_adapter(stage: str) -> ScannerAdapter:
    mode = get_settings().scanner_mode.lower()
    table = _FAKE if mode == "fake" else _REAL
    try:
        return table[stage]()
    except KeyError as exc:
        raise ValueError(f"no adapter registered for stage {stage!r}") from exc


def passive_stages() -> list[str]:
    return [STAGE_SUBFINDER, STAGE_DNSX]
