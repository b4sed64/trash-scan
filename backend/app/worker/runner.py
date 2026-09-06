"""Stage orchestration for a single execution (passive and active).

Kept separate from the Celery task wrapper so it can be unit-tested by calling
``execute(execution_id)`` directly.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os

from ..adapters import StageInput, get_adapter
from ..adapters.base import (
    STAGE_DNSX,
    STAGE_HTTPX,
    STAGE_NMAP,
    STAGE_NUCLEI,
    STAGE_SUBFINDER,
)
from ..config import get_settings
from ..db import SessionLocal
from ..models import ScanExecution
from ..scan_profiles import profile_for
from ..services.audit_service import AuditService
from ..services.emergency import active_stop, blocks_execution
from ..services.execution_service import TERMINAL, ScanService
from ..services import comparison as comparison_service
from ..services.findings import record_findings
from ..services.normalization import apply_stage_outputs
from ..services.scope_db import evaluate_target_scope, load_private_cidrs

_NON_START = {"DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED"}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _limits() -> dict:
    s = get_settings()
    return {
        "dns_qps": s.dns_queries_per_second,
        "http_rps": s.http_requests_per_second,
        "nuclei_rps": s.nuclei_requests_per_second,
        "stage_timeout": min(s.max_runtime_minutes * 60, 1800),
    }


def _result_dir(execution_id: str) -> str:
    path = os.path.join(get_settings().result_root, execution_id)
    os.makedirs(path, exist_ok=True)
    return path


def _within_scope(ip: str, private_cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in private_cidrs)


def _guard_factory(execution_id: str):
    """Poll cancellation and the runtime deadline (~1/s)."""
    def check() -> bool:
        with SessionLocal() as db:
            ex = db.get(ScanExecution, execution_id)
            if ex is None:
                return True
            if ex.cancel_requested:
                return True
            deadline = _aware(ex.runtime_deadline_at)
            return bool(deadline and _now() > deadline)
    return check


def execute(execution_id: str, *, enqueue=None) -> str:  # noqa: C901 - lifecycle is inherently branchy
    settings = get_settings()

    # --- pre-flight (single short transaction) --------------------------
    with SessionLocal() as db:
        ex = db.get(ScanExecution, execution_id)
        if ex is None:
            return "MISSING"
        if ex.state in TERMINAL:
            return ex.state

        stop = active_stop(db)
        if blocks_execution(stop, ex) and ex.state != "RUNNING":
            ScanService.transition(db, ex, "CANCELLED", actor="system:worker",
                                   reason="emergency stop active")
            db.commit()
            return "CANCELLED"

        if ex.cancel_requested and ex.state in _NON_START:
            ScanService.transition(db, ex, "CANCELLED", actor="system:worker",
                                   reason=ex.cancel_reason or "cancelled before start")
            db.commit()
            return "CANCELLED"

        if ex.state == "QUEUED" and not ScanService.capacity_available(db, ex):
            return "QUEUED"  # lifecycle_sweep re-enqueues when a slot frees

        classification = ex.classification
        profile_name = ex.profile
        ex_options = dict(ex.options or {})
        target_kind = ex.target.kind
        target_value = ex.target.value
        private_cidrs = load_private_cidrs(db)
        in_scope_ips: list[str] = []

        if classification == "ACTIVE":
            expires = _aware(ex.approval_expires_at)
            if ex.state in _NON_START and expires and _now() > expires:
                ScanService.transition(db, ex, "EXPIRED", actor="system:worker",
                                       reason="approval window elapsed before start")
                db.commit()
                return "EXPIRED"

            # SCOPE-07: re-resolve and re-evaluate immediately before launch.
            decision = evaluate_target_scope(db, ex.target)
            literal_ips: list[str] = []
            if target_kind == "IPV4":
                literal_ips = [target_value]
            elif target_kind == "CIDR":
                net = ipaddress.ip_network(target_value, strict=False)
                literal_ips = [str(h) for h in list(net.hosts())[:1024]] or [str(net.network_address)]
            candidate_ips = sorted(set(decision.resolved_addresses) | set(literal_ips))
            in_scope_ips = [ip for ip in candidate_ips if _within_scope(ip, private_cidrs)]

            if not decision.allowed or not in_scope_ips:
                ScanService.transition(
                    db, ex, "FAILED", actor="system:worker",
                    reason=f"scope re-check failed before launch: {decision.reason}",
                    extra_payload={"resolved": decision.resolved_addresses},
                )
                AuditService.append(
                    db, actor="system:worker", action="SCAN_SCOPE_RECHECK_FAILED",
                    object_type="scan_execution", object_id=ex.id,
                    payload=decision.as_audit_payload(),
                )
                db.commit()
                return "FAILED"

            AuditService.append(
                db, actor="system:worker", action="SCAN_SCOPE_RECHECK_PASSED",
                object_type="scan_execution", object_id=ex.id,
                payload={"in_scope_addresses": in_scope_ips},
            )

        if ex.state == "QUEUED":
            ScanService.transition(db, ex, "RUNNING", actor="system:worker",
                                   extra_payload={"classification": classification})
        elif ex.state != "RUNNING":
            db.commit()
            return ex.state

        result_dir = _result_dir(execution_id)
        ex.result_dir = result_dir
        db.commit()

    # --- run stages (no DB session held while subprocesses run) ----------
    limits = _limits()
    resolvers = settings.resolver_list()
    guard = _guard_factory(execution_id)
    profile = profile_for(profile_name)

    stage_outputs, stage_meta = [], []
    tool_versions: dict[str, str] = {}
    normalized_args: dict[str, list[str]] = {}
    incomplete = False
    discovered_hosts: list[str] = []
    web_probes: list[str] = []

    plan = [s for s in profile.stages if not (s == STAGE_SUBFINDER and target_kind != "DOMAIN")]

    for stage_name in plan:
        if guard():
            incomplete = True
            break
        adapter = get_adapter(stage_name)
        if stage_name == STAGE_SUBFINDER:
            hosts = []
        elif stage_name == STAGE_DNSX:
            hosts = list(discovered_hosts)
        elif stage_name == STAGE_NMAP:
            hosts = list(in_scope_ips)
        elif stage_name in (STAGE_HTTPX, STAGE_NUCLEI):
            hosts = sorted(set(web_probes) | set(in_scope_ips))
        else:
            hosts = []

        options = dict()
        options["_cancel_check"] = guard
        options["_private_cidrs"] = private_cidrs
        options["syn"] = profile.nmap_syn
        options["os_detection"] = profile.nmap_os_detection
        options["service_detection"] = profile.nmap_service_detection
        options["ports"] = (ex_options or {}).get("ports")
        inp = StageInput(
            stage=stage_name, target_kind=target_kind, target_value=target_value,
            profile=profile_name, hosts=hosts, options=options, limits=limits,
            result_dir=result_dir, resolvers=resolvers,
        )
        out = adapter.run(inp)
        stage_outputs.append(out)
        tool_versions[out.tool] = out.tool_version
        normalized_args[stage_name] = out.args
        stage_meta.append({
            "stage": stage_name, "tool": out.tool, "ok": out.ok, "incomplete": out.incomplete,
            "duration_ms": out.duration_ms, "assets": len(out.assets),
            "services": len(out.services), "observations": len(out.observations),
            "stderr_excerpt": out.stderr_excerpt[:500], "note": out.note,
        })
        incomplete = incomplete or out.incomplete or not out.ok
        for a in out.assets:
            if a.kind == "HOSTNAME" and a.value not in discovered_hosts:
                discovered_hosts.append(a.value)
        for o in out.observations:
            if o.kind == "TECH" and o.key == "web-port" and o.value not in web_probes:
                web_probes.append(o.value)

    # --- persist results ----------------------------------------------
    with SessionLocal() as db:
        ex = db.get(ScanExecution, execution_id)
        if ex.state in TERMINAL:
            return ex.state

        ex.stages = stage_meta
        ex.tool_versions = tool_versions
        ex.normalized_args = normalized_args
        ex.parser_version = "4"

        try:
            summary = apply_stage_outputs(db, ex, stage_outputs)
            summary.update(record_findings(db, ex, stage_outputs))
        except Exception as exc:  # noqa: BLE001 - a parser must not crash the worker
            db.rollback()
            ex = db.get(ScanExecution, execution_id)
            ScanService.transition(db, ex, "FAILED", actor="system:worker",
                                   reason=f"normalization error: {exc}")
            db.commit()
            return "FAILED"

        deadline = _aware(ex.runtime_deadline_at)
        timed_out = bool(deadline and _now() > deadline)

        if timed_out:
            ex.partial = True
            ScanService.transition(db, ex, "TIMED_OUT", actor="system:worker",
                                   reason="maximum runtime reached", extra_payload=summary)
            AuditService.append(db, actor="system:worker", action="SCAN_TERMINATED",
                                object_type="scan_execution", object_id=ex.id,
                                payload={"reason": "TIMED_OUT"})
            db.commit()
            return "TIMED_OUT"

        if ex.cancel_requested:
            ScanService.transition(db, ex, "CANCELLING", actor="system:worker",
                                   reason=ex.cancel_reason or "cancelled")
            ex.partial = True
            ScanService.transition(db, ex, "CANCELLED", actor="system:worker",
                                   extra_payload=summary)
            db.commit()
            return "CANCELLED"

        ex.partial = incomplete
        if any(m["stage"] == "nuclei" for m in stage_meta):
            ex.template_set_hash = _nuclei_template_hash()
        ScanService.transition(db, ex, "COMPLETED", actor="system:worker",
                               extra_payload={**summary, "partial": incomplete})
        AuditService.append(
            db, actor="system:worker", action="SCAN_RESULTS_NORMALIZED",
            object_type="scan_execution", object_id=ex.id,
            payload={**summary, "tool_versions": tool_versions,
                     "stages": [m["stage"] for m in stage_meta]},
        )
        db.flush()
        comparison_service.build_and_store(db, ex)
        db.commit()
        return "COMPLETED"


def _nuclei_template_hash() -> str:
    try:
        from ..adapters.nuclei import template_set_hash

        return template_set_hash()
    except Exception:  # noqa: BLE001
        return ""
