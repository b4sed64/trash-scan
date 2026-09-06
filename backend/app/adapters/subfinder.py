"""Subfinder adapter — passive public subdomain discovery (PRD §12.2).

Free/keyless sources only: we never pass ``-all`` and never provide a provider
config, so key-only sources are simply skipped. Returned names are *discoveries*,
not authorized targets.
"""
from __future__ import annotations

import json
import os

from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_PASSIVE,
    STAGE_SUBFINDER,
    DiscoveredAsset,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_SUBFINDER_BIN", "subfinder")


class SubfinderAdapter:
    stage = STAGE_SUBFINDER
    classification = CLASSIFICATION_PASSIVE

    def tool_version(self) -> str:
        return _tool_version(BIN)

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="subfinder",
                          tool_version=self.tool_version())
        if inp.target_kind != "DOMAIN":
            out.note = "subfinder only applies to domain targets"
            return out

        outfile = os.path.join(inp.result_dir, "subfinder.jsonl")
        rate = str(int(inp.limits.get("dns_qps", 20)))
        argv = [
            BIN,
            "-silent",
            "-oJ",
            "-o", outfile,
            "-rate-limit", rate,
            "-timeout", "20",
            "-disable-update-check",
            "-no-color",
            "-d", inp.target_value,
        ]
        out.args = argv[1:]
        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 600)),
                           cwd=inp.result_dir)
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "subfinder binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out
        out.assets = list(_parse(_read_lines(outfile, res.stdout)))
        # subfinder exits 0 on "no results"; a non-zero code with no output is a
        # real failure.
        out.ok = res.returncode == 0 or bool(out.assets)
        return out


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _parse(lines: list[str]):
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        if host and host not in seen and _looks_like_host(host):
            seen.add(host)
            yield DiscoveredAsset(kind="HOSTNAME", value=host, source="subfinder")


def _looks_like_host(host: str) -> bool:
    return (
        1 < len(host) <= 253
        and "." in host
        and all(1 <= len(lbl) <= 63 for lbl in host.split("."))
        and all(c.isalnum() or c in "-." for c in host)
    )
