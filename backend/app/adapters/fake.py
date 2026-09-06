"""Deterministic fake adapters.

Selected when ``TRASHSCAN_SCANNER_MODE=fake`` (and always in tests). Output is a
pure function of the target so parsers, normalization and the execution
lifecycle can be exercised without any network traffic.
"""
from __future__ import annotations

import hashlib

from .base import (
    CLASSIFICATION_PASSIVE,
    STAGE_DNSX,
    STAGE_SUBFINDER,
    DiscoveredAsset,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

FAKE_VERSION = "fake/2.0.0"


def _octet(seed: str, salt: str) -> int:
    return hashlib.sha256(f"{seed}:{salt}".encode()).digest()[0] % 254 + 1


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
        return out


def _is_ipish(v: str) -> bool:
    return all(part.isdigit() for part in v.split(".") if part) and v.count(".") == 3
