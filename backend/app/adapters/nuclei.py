"""Nuclei adapter — reviewed detection of exposures and misconfigurations (PRD §12.5).

Hard restrictions:
  * templates come only from the immutable in-repo allowlist directory, and each
    file's sha256 is verified against ``manifest.json`` before every run;
  * automatic template/binary updates are disabled;
  * dangerous template categories are excluded by tag as defence in depth;
  * no interactsh / out-of-band, no workflows, no user-supplied templates.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_NUCLEI,
    DiscoveredFinding,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_NUCLEI_BIN", "nuclei")
TEMPLATE_DIR = Path(os.getenv("TRASHSCAN_NUCLEI_TEMPLATES", "/app/templates/nuclei"))
_EXCLUDE_TAGS = "fuzz,fuzzing,dos,intrusive,brute-force,bruteforce,creds-stuffing,rce,sqli,xss,oast"
_SEV_MAP = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_path(template_dir: Path) -> Path:
    return template_dir.parent / "nuclei-manifest.json"


def verify_template_set(template_dir: Path = TEMPLATE_DIR) -> tuple[bool, dict[str, str], str]:
    """Return (ok, {file: hash}, reason). ok is False if any file is missing,
    extra, or altered relative to the reviewed manifest."""
    manifest_path = _manifest_path(template_dir)
    if not manifest_path.exists():
        return False, {}, "nuclei-manifest.json is missing"
    expected: dict[str, str] = json.loads(manifest_path.read_text()).get("templates", {})
    present = {p.name: _sha256(p) for p in sorted(template_dir.glob("*.yaml"))}
    if set(present) != set(expected):
        return False, present, (
            f"template set differs from manifest: "
            f"missing={sorted(set(expected) - set(present))} "
            f"extra={sorted(set(present) - set(expected))}"
        )
    for name, digest in present.items():
        if digest != expected[name]:
            return False, present, f"template {name} content hash does not match manifest"
    return True, present, ""


def template_set_hash(template_dir: Path = TEMPLATE_DIR) -> str:
    ok, present, _ = verify_template_set(template_dir)
    if not ok:
        return ""
    blob = json.dumps(present, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class NucleiAdapter:
    stage = STAGE_NUCLEI
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN, "-version")

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="nuclei",
                          tool_version=self.tool_version())

        ok, hashes, reason = verify_template_set()
        if not ok:
            out.ok = False
            out.incomplete = True
            out.note = f"template allowlist verification failed: {reason}"
            out.stderr_excerpt = reason
            return out

        probes = sorted({h for h in inp.hosts if h})
        if not probes:
            out.note = "no approved hosts to probe"
            return out

        infile = os.path.join(inp.result_dir, "nuclei_input.txt")
        outfile = os.path.join(inp.result_dir, "nuclei.jsonl")
        with open(infile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(probes) + "\n")

        rps = str(int(inp.limits.get("nuclei_rps", get_settings().nuclei_requests_per_second)))
        argv = [
            BIN, "-jsonl", "-o", outfile, "-silent", "-no-color",
            "-disable-update-check", "-duc",
            "-t", str(TEMPLATE_DIR),
            "-exclude-tags", _EXCLUDE_TAGS,
            "-rate-limit", rps,
            "-timeout", "10", "-retries", "1",
            "-no-interactsh",
            "-l", infile,
        ]
        out.args = argv[1:]

        try:
            res = run_tool(argv, timeout_seconds=int(inp.limits.get("stage_timeout", 900)),
                           cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"))
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "nuclei binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        lines = _read_lines(outfile, res.stdout)
        out.findings = list(_parse(lines, hashes))
        out.ok = res.returncode == 0 or bool(out.findings)
        return out


def _read_lines(path: str, fallback: bytes) -> list[str]:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return fallback.decode("utf-8", errors="replace").splitlines()


def _parse(lines: list[str], template_hashes: dict[str, str]):
    settings = get_settings()
    evidence_cap = settings.max_evidence_bytes
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule_id = str(row.get("template-id") or row.get("templateID") or "")
        if not rule_id:
            continue
        info = row.get("info") or {}
        severity = _SEV_MAP.get(str(info.get("severity", "info")).lower(), "INFO")
        matched_at = str(row.get("matched-at") or row.get("host") or "")
        host = str(row.get("host") or "").split("://")[-1].split("/")[0].split(":")[0]
        matcher = str(row.get("matcher-name") or "")
        extracted = row.get("extracted-results") or []
        port = None
        try:
            port = int(str(row.get("port") or "").strip() or 0) or None
        except ValueError:
            port = None

        tmpl_path = str(row.get("template-path") or row.get("template") or "")
        tmpl_name = os.path.basename(tmpl_path)
        tmpl_hash = template_hashes.get(tmpl_name, "")

        # evidence_key excludes volatile data (timestamps, curl commands, raw bodies).
        evidence_key = "|".join(
            [rule_id, matcher] + [str(e)[:80] for e in extracted[:3]]
        )[:200]
        summary = (
            f"{info.get('name', rule_id)} at {matched_at}"
            + (f" — matcher {matcher}" if matcher else "")
            + (f" — {', '.join(str(e) for e in extracted[:3])}" if extracted else "")
        )[:evidence_cap]

        yield DiscoveredFinding(
            rule_id=rule_id,
            template_hash=tmpl_hash,
            severity=severity,
            name=str(info.get("name", rule_id))[:256],
            description=str(info.get("description", ""))[:2000],
            asset_value=host,
            matched_at=matched_at[:256],
            matcher_name=matcher[:128],
            port=port,
            protocol="tcp",
            evidence_key=evidence_key,
            evidence_summary=summary,
            evidence={"matched_at": matched_at[:256], "matcher": matcher[:128],
                      "extracted": [str(e)[:120] for e in extracted[:5]]},
        )
