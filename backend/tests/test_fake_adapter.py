"""The fake adapters must be deterministic and passive-only."""
from __future__ import annotations

from app.adapters.base import StageInput
from app.adapters.fake import FakeDnsxAdapter, FakeSubfinderAdapter


def _inp(kind: str, value: str, **kw) -> StageInput:
    return StageInput(stage="x", target_kind=kind, target_value=value, profile="PASSIVE", **kw)


def test_subfinder_only_for_domains():
    assert FakeSubfinderAdapter().run(_inp("IPV4", "10.10.5.20")).assets == []
    out = FakeSubfinderAdapter().run(_inp("DOMAIN", "example.com"))
    assert any(a.value == "www.example.com" for a in out.assets)


def test_dnsx_deterministic():
    a = FakeDnsxAdapter().run(_inp("DOMAIN", "example.com", hosts=["www.example.com"]))
    b = FakeDnsxAdapter().run(_inp("DOMAIN", "example.com", hosts=["www.example.com"]))
    assert [x.value for x in a.assets] == [x.value for x in b.assets]
    assert all(o.kind == "DNS_RECORD" for o in a.observations)


def test_dnsx_ip_target_produces_ptr():
    out = FakeDnsxAdapter().run(_inp("IPV4", "10.10.5.20"))
    assert any(a.value == "10.10.5.20" for a in out.assets)
    assert any(o.key == "PTR" for o in out.observations)
