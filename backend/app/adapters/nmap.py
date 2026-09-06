"""Nmap adapter — TCP port discovery and service estimation (PRD §12.1).

Hard restrictions enforced here:
  * no spoofing, decoys, fragmentation or timing-evasion options;
  * no NSE scripts;
  * no user-supplied flags — every argument comes from the profile + config;
  * SYN scan (``-sS``) and OS detection (``-O``) are only added when
    ``allow_raw_packet`` is enabled; otherwise a TCP connect scan (``-sT``) is
    used and OS detection is skipped.
  * targets are the pre-resolved in-scope IPs, never a hostname.
"""
from __future__ import annotations

import os

import defusedxml.ElementTree as ET
from defusedxml.ElementTree import ParseError

from ..config import get_settings
from ._exec import ToolNotFound, excerpt, run_tool
from ._exec import tool_version as _tool_version
from .base import (
    CLASSIFICATION_ACTIVE,
    STAGE_NMAP,
    DiscoveredObservation,
    DiscoveredService,
    StageInput,
    StageOutput,
)

BIN = os.getenv("TRASHSCAN_NMAP_BIN", "nmap")
_WEBBISH = {"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http"}


class NmapAdapter:
    stage = STAGE_NMAP
    classification = CLASSIFICATION_ACTIVE

    def tool_version(self) -> str:
        return _tool_version(BIN, "--version")

    def run(self, inp: StageInput) -> StageOutput:
        out = StageOutput(stage=self.stage, ok=True, tool="nmap", tool_version=self.tool_version())
        settings = get_settings()
        want_syn = bool(inp.options.get("syn"))
        want_os = bool(inp.options.get("os_detection"))
        want_service = bool(inp.options.get("service_detection", True))

        scan_targets = list(inp.hosts) or ([inp.target_value] if inp.target_kind == "CIDR" else [])
        scan_targets = [t for t in scan_targets if _is_ip_or_cidr(t)]
        if not scan_targets:
            out.note = "no resolved in-scope IPs to scan"
            return out

        outfile = os.path.join(inp.result_dir, "nmap.xml")
        ports = str(inp.options.get("ports") or settings.ports_for_profile(inp.profile))
        timing = settings.timing_for_profile(inp.profile)

        argv = [BIN, "-oX", outfile, "-Pn", "-n", f"-{timing}", "--host-timeout", "1800s",
                "--max-retries", "2", "-p", ports]

        if want_syn and settings.allow_raw_packet:
            argv.append("-sS")
        else:
            argv.append("-sT")
        if want_service:
            argv += ["-sV", "--version-intensity", "2"]
        if want_os and settings.allow_raw_packet:
            argv += ["-O", "--osscan-limit"]

        argv += scan_targets
        out.args = argv[1:]

        try:
            res = run_tool(
                argv, timeout_seconds=int(inp.limits.get("stage_timeout", 1800)),
                cwd=inp.result_dir, should_cancel=inp.options.get("_cancel_check"),
            )
        except ToolNotFound:
            out.ok = False
            out.incomplete = True
            out.stderr_excerpt = "nmap binary not found in worker image"
            return out

        out.duration_ms = res.duration_ms
        out.raw_path = outfile if os.path.exists(outfile) else None
        out.stderr_excerpt = excerpt(res.stderr)
        out.incomplete = res.timed_out

        xml_text = _read(outfile) or res.stdout.decode("utf-8", errors="replace")
        services, observations, parsed = _parse_xml(xml_text)
        out.services = services
        out.observations = observations
        out.ok = parsed and res.returncode == 0
        if not parsed:
            out.incomplete = True
            out.note = "nmap XML was missing or unparseable"
        return out


def _is_ip_or_cidr(v: str) -> bool:
    import ipaddress

    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _read(path: str) -> str | None:
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    return None


def _parse_xml(text: str) -> tuple[list[DiscoveredService], list[DiscoveredObservation], bool]:
    services: list[DiscoveredService] = []
    observations: list[DiscoveredObservation] = []
    if not text or "<nmaprun" not in text:
        return services, observations, False
    try:
        root = ET.fromstring(text)
    except ParseError:
        # Truncated output: salvage complete <host> blocks.
        cut = text.rfind("</host>")
        if cut == -1:
            return services, observations, False
        try:
            root = ET.fromstring(text[: cut + len("</host>")] + "</nmaprun>")
        except ParseError:
            return services, observations, False

    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state not in ("open", "open|filtered"):
                    continue
                svc = p.find("service")
                services.append(DiscoveredService(
                    asset_value=addr,
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),
                    state=state,
                    product=(svc.get("product", "") if svc is not None else ""),
                    version=(svc.get("version", "") if svc is not None else ""),
                    confidence=(svc.get("conf", "") if svc is not None else ""),
                ))
                if svc is not None and (svc.get("name", "") in _WEBBISH or svc.get("tunnel") == "ssl"):
                    observations.append(DiscoveredObservation(
                        kind="TECH", key="web-port", value=f"{addr}:{p.get('portid')}",
                        source="nmap", asset_value=addr,
                    ))
        os_el = host.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch")[:2]:
                observations.append(DiscoveredObservation(
                    kind="OSINT", key="os-guess",
                    value=f"{m.get('name', '')} (accuracy {m.get('accuracy', '?')}%)",
                    source="nmap", asset_value=addr,
                ))
    return services, observations, True
