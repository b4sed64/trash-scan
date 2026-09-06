"""Tool-output parsers must tolerate malformed / truncated lines (NFR-06)."""
from __future__ import annotations

from pathlib import Path

from app.adapters.dnsx import _parse as dnsx_parse
from app.adapters.subfinder import _parse as subfinder_parse

FIX = Path(__file__).parent / "fixtures"


def _lines(name: str) -> list[str]:
    return (FIX / name).read_text().splitlines()


def test_subfinder_parser_dedupes_and_normalizes():
    assets = list(subfinder_parse(_lines("subfinder.jsonl")))
    values = sorted(a.value for a in assets)
    assert values == [
        "api.lab.example.com",
        "mail.lab.example.com",
        "vpn.lab.example.com",
        "www.lab.example.com",
    ]
    assert all(a.kind == "HOSTNAME" and a.source == "subfinder" for a in assets)


def test_dnsx_parser_extracts_assets_and_records():
    assets, observations = dnsx_parse(_lines("dnsx.jsonl"))
    ips = sorted(a.value for a in assets if a.kind == "IP")
    assert "10.10.5.20" in ips and "10.10.5.21" in ips and "203.0.113.9" in ips

    kinds = {(o.key, o.value) for o in observations}
    assert ("A", "10.10.5.20") in kinds
    assert ("CNAME", "lab.example.com") in kinds
    assert ("PTR", "gw.lab.example.com") in kinds
    assert any(o.key == "NS" for o in observations)
    # a truncated JSON line does not raise
    assert observations


def test_parsers_handle_empty_input():
    assert list(subfinder_parse([])) == []
    assert dnsx_parse([]) == ([], [])
