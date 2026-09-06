"""The fake passive adapter must be deterministic and passive-only."""
from __future__ import annotations

from app.adapters import FakePassiveAdapter
from app.adapters.base import ScanInput


def test_deterministic_output():
    a = FakePassiveAdapter().run(ScanInput("DOMAIN", "example.com", "PASSIVE"))
    b = FakePassiveAdapter().run(ScanInput("DOMAIN", "example.com", "PASSIVE"))
    assert a.ok and b.ok
    assert [x.value for x in a.assets] == [x.value for x in b.assets]
    assert a.tool_version == b.tool_version


def test_rejects_active_profiles():
    result = FakePassiveAdapter().run(ScanInput("IPV4", "10.10.5.20", "STANDARD_ACTIVE"))
    assert result.ok is False
    assert result.assets == []
