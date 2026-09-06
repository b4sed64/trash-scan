"""Deterministic fake passive-discovery adapter.

Used for frontend work and backend tests so parsers and workflows can be
exercised without sending any network traffic (PRD 26 / Phase 1). Output is a
pure function of the target value.
"""
from __future__ import annotations

import hashlib

from .base import AdapterResult, DiscoveredAsset, ScanInput

FAKE_TOOL_VERSION = "fake-adapter/1.0.0"


def _stable_octet(seed: str, salt: str) -> int:
    digest = hashlib.sha256(f"{seed}:{salt}".encode()).digest()
    return digest[0] % 254 + 1


class FakePassiveAdapter:
    name = "fake-passive"
    classification = "PASSIVE"

    def run(self, scan: ScanInput) -> AdapterResult:
        if scan.profile != "PASSIVE":
            return AdapterResult(
                ok=False,
                tool=self.name,
                tool_version=FAKE_TOOL_VERSION,
                stderr="fake passive adapter only supports the PASSIVE profile",
            )

        assets: list[DiscoveredAsset] = []
        value = scan.target_value

        if scan.target_kind == "DOMAIN":
            for label in ("www", "api", "vpn", "mail"):
                assets.append(
                    DiscoveredAsset(kind="HOSTNAME", value=f"{label}.{value}", source=self.name)
                )
            a = _stable_octet(value, "a")
            b = _stable_octet(value, "b")
            assets.append(DiscoveredAsset(kind="IP", value=f"10.{a}.{b}.10", source=self.name))
            # A deliberately out-of-scope discovery to exercise the "unapproved" path.
            assets.append(
                DiscoveredAsset(kind="HOSTNAME", value=f"cdn.{value}.example.net", source=self.name)
            )
        elif scan.target_kind in ("IPV4", "CIDR"):
            base = value.split("/")[0].rsplit(".", 1)[0]
            for host in (1, 10, 20):
                assets.append(
                    DiscoveredAsset(kind="IP", value=f"{base}.{host}", source=self.name)
                )

        return AdapterResult(
            ok=True,
            tool=self.name,
            tool_version=FAKE_TOOL_VERSION,
            assets=assets,
        )
