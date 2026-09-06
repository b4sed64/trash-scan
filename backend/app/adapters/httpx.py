"""ProjectDiscovery httpx adapter — HTTP inspection (PRD §12.4).

Restrictions enforced here:
  * probe only the approved hosts/addresses passed in ``inp.hosts``;
  * bounded redirects (not followed by default — the Location header is captured
    and scope-checked by the caller), response size, retries, timeout, rate;
  * no arbitrary methods, paths, unsafe mode, or user-defined headers.
This is NOT the Python ``httpx`` client library.
"""
from __future__ import annotations

import ipaddress
import json
import os

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_HTTPX,
    DiscoveredObservation,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_HTTPX_BIN", "httpx-pd")


class HttpxAdapter:
    stage = STAGE_HTTPX
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN)

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="httpx", tool_version=self.tool_version())
        settings = get_settings()

        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to probe"
            return out

        infile = os.path.join(inp.result_dir, "httpx_input.txt")
        outfile = os.path.join(inp.result_dir, "httpx.jsonl")
        with open(infile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(probes) + "\n")

        rps = str(int(inp.limits.get("http_rps", settings.http_requests_per_second)))
        argv = [
            BIN, "-silent", "-json", "-no-color", "-disable-update-check",
            "-l", infile, "-o", outfile,
            "-status-code", "-title", "-tech-detect", "-content-type", "-web-server",
            "-location", "-tls-grab", "-response-time",
            "-timeout", "10", "-retries", "1",
            "-rate-limit", rps,
            "-max-response-size", str(int(settings.max_response_bytes)),
        ]
        if settings.httpx_follow_redirects:
            argv += ["-follow-redirects", "-max-redirects", str(int(settings.httpx_max_redirects))]
        out.args = argv[1:]

        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 900)),
                           cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"))
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "httpx binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        lines = _read_lines(outfile, res.stdout)
        out.observations = list(_parse(lines, inp))
        out.ok = res.returncode == 0 or bool(out.observations)
        return out


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _in_scope(host: str, private_cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname — scope was already checked before the stage
    return any(addr in ipaddress.ip_network(c, strict=False) for c in private_cidrs)


def _parse(lines: list[str], inp: StageInput):
    private_cidrs = list(inp.options.get("_private_cidrs") or [])
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host") or row.get("input") or "")
        url = str(row.get("url") or "")
        anchor = host or url

        if row.get("status_code") is not None:
            yield DiscoveredObservation(kind="HTTP_STATUS", key=url or host,
                                       value=str(row["status_code"]), source="httpx",
                                       asset_value=host or None)
        if row.get("title"):
            yield DiscoveredObservation(kind="TITLE", key=anchor, value=str(row["title"])[:300],
                                       source="httpx", asset_value=host or None)
        if row.get("webserver"):
            yield DiscoveredObservation(kind="HTTP_HEADER", key="Server",
                                       value=str(row["webserver"]), source="httpx",
                                       asset_value=host or None)
        if row.get("content_type"):
            yield DiscoveredObservation(kind="HTTP_HEADER", key="Content-Type",
                                       value=str(row["content_type"]), source="httpx",
                                       asset_value=host or None)
        for tech in row.get("tech") or row.get("technologies") or []:
            yield DiscoveredObservation(kind="TECH", key="tech", value=str(tech)[:80],
                                       source="httpx", asset_value=host or None)
        tls = row.get("tls") or {}
        if tls:
            subj = tls.get("subject_cn") or tls.get("subject_dn") or ""
            issuer = tls.get("issuer_cn") or tls.get("issuer_dn") or ""
            expiry = tls.get("not_after") or ""
            yield DiscoveredObservation(kind="TLS", key="certificate",
                                       value=f"subject={subj}; issuer={issuer}; not_after={expiry}"[:400],
                                       source="httpx", asset_value=host or None)
        loc = row.get("location")
        if loc:
            in_scope = _in_scope(str(loc).split("/")[2] if "//" in str(loc) else "", private_cidrs)
            yield DiscoveredObservation(
                kind="HTTP_HEADER", key="Location",
                value=f"{loc}" + ("" if in_scope else "  [OUT OF APPROVED SCOPE — not followed]"),
                source="httpx", asset_value=host or None,
            )
