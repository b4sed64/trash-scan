"""ProjectDiscovery katana adapter — bounded web crawling (PRD §12.7).

Approved responsibilities:
  * discover additional in-scope endpoints (pages, JS-referenced routes, known
    files) reachable from the web hosts httpx already probed this execution;
  * feed those endpoints back into this same execution's Nuclei stage.

Restrictions enforced here:
  * crawl only the hosts passed in ``inp.hosts`` — never a host outside scope,
    and default host-based scope (``-fs rdn``) is left on, so the crawler
    itself never leaves the seed host's registrable domain;
  * bounded crawl depth (by profile, like Nmap's timing template), bounded
    pages per host, bounded time budget, bounded request rate — all
    product-fixed, never a user-supplied or arbitrary flag;
  * no headless/browser-based crawling (JavaScript is parsed statically for
    endpoints, never executed), no automatic form filling, no live secret
    validation API calls;
  * discovered endpoints are unapproved discoveries, exactly like every other
    adapter's assets/observations.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_KATANA,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_KATANA_BIN", "katana")


class KatanaAdapter:
    stage = STAGE_KATANA
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN)

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="katana", tool_version=self.tool_version())
        settings = get_settings()

        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to crawl"
            return out

        infile = os.path.join(inp.result_dir, "katana_input.txt")
        outfile = os.path.join(inp.result_dir, "katana.jsonl")
        with open(infile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(probes) + "\n")

        depth = settings.katana_depth_for_profile(inp.profile)
        rps = str(int(inp.limits.get("http_rps", settings.http_requests_per_second)))
        argv = [
            BIN, "-silent", "-jsonl", "-no-color", "-disable-update-check",
            "-list", infile, "-output", outfile,
            "-depth", str(depth),
            "-max-domain-pages", str(int(settings.katana_max_pages_per_host)),
            "-crawl-duration", f"{int(settings.katana_crawl_duration_seconds)}s",
            "-concurrency", "5", "-parallelism", "2",
            "-rate-limit", rps,
            "-timeout", "10", "-retry", "1",
            "-max-response-size", str(int(settings.max_response_bytes)),
            "-js-crawl",
        ]
        out.args = argv[1:]

        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 900)),
                           cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"))
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "katana binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        lines = _read_lines(outfile, res.stdout)
        out.observations = _parse(lines)
        out.ok = res.returncode == 0 or bool(out.observations)
        return out


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _parse(lines: list[str]) -> list[DiscoveredObservation]:
    """katana's jsonl rows nest the crawled URL as request.endpoint; there is no
    top-level host field, so it's derived from the URL itself."""
    observations: list[DiscoveredObservation] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        endpoint = str((row.get("request") or {}).get("endpoint") or "").strip()
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)
        host = urlparse(endpoint).hostname or None
        observations.append(DiscoveredObservation(
            kind="TECH", key="endpoint", value=endpoint[:300], source="katana", asset_value=host,
        ))
    return observations
