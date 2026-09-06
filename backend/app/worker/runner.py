"""Stage orchestration for a single execution.

Kept separate from the Celery task wrapper so it can be unit-tested by calling
``execute(execution_id)`` directly.
"""
from __future__ import annotations

import datetime as dt
import os

from ..adapters import StageInput, get_adapter
from ..adapters.base import STAGE_DNSX, STAGE_SUBFINDER
from ..config import get_settings
from ..db import SessionLocal
from ..models import ScanExecution
from ..services.audit_service import AuditService
from ..services.execution_service import ScanService
from ..services.normalization import apply_stage_outputs


def _limits() -> dict:
    s = get_settings()
    return {
        "dns_qps": s.dns_queries_per_second,
        "http_rps": s.http_requests_per_second,
        "stage_timeout": min(s.max_runtime_minutes * 60, 1800),
    }


def _result_dir(execution: ScanExecution) -> str:
    root = get_settings().result_root
    path = os.path.join(root, execution.id)
    os.makedirs(path, exist_ok=True)
    return path


def _cancel_check(execution_id: str):
    def check() -> bool:
        with SessionLocal() as db:
            ex = db.get(ScanExecution, execution_id)
            return bool(ex and ex.cancel_requested)
    return check


def execute(execution_id: str, *, enqueue=None) -> str:
    """Run one execution to a terminal state. Returns the final state."""
    with SessionLocal() as db:
        execution = db.get(ScanExecution, execution_id)
        if execution is None:
            return "MISSING"
        if execution.state in {"COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"}:
            return execution.state

        if execution.cancel_requested and execution.state in {"QUEUED", "APPROVED"}:
            ScanService.transition(db, execution, "CANCELLED", actor="system:worker",
                                   reason=execution.cancel_reason or "cancelled before start")
            db.commit()
            return "CANCELLED"

        if execution.state == "QUEUED" and not ScanService.capacity_available(db, execution):
            # Leave QUEUED; lifecycle_sweep will re-enqueue when a slot frees.
            return "QUEUED"

        if execution.state == "QUEUED":
            ScanService.transition(db, execution, "RUNNING", actor="system:worker")
            db.commit()
        elif execution.state != "RUNNING":
            return execution.state

        result_dir = _result_dir(execution)
        execution.result_dir = result_dir
        db.commit()

        target_kind = execution.target.kind
        target_value = execution.target.value

    # --- run stages (no DB session held while subprocesses run) -----------
    settings = get_settings()
    limits = _limits()
    resolvers = settings.resolver_list()
    should_cancel = _cancel_check(execution_id)
    stage_outputs = []
    stage_meta = []
    tool_versions: dict[str, str] = {}
    normalized_args: dict[str, list[str]] = {}
    incomplete = False

    plan = []
    if execution.classification == "PASSIVE":
        if target_kind == "DOMAIN":
            plan.append(STAGE_SUBFINDER)
        plan.append(STAGE_DNSX)

    discovered_hosts: list[str] = []
    for stage_name in plan:
        if should_cancel():
            incomplete = True
            break
        adapter = get_adapter(stage_name)
        hosts = list(discovered_hosts)
        inp = StageInput(
            stage=stage_name, target_kind=target_kind, target_value=target_value,
            profile=execution.profile, hosts=hosts, options=execution.options or {},
            limits=limits, result_dir=result_dir, resolvers=resolvers,
        )
        out = adapter.run(inp)
        stage_outputs.append(out)
        tool_versions[out.tool] = out.tool_version
        normalized_args[stage_name] = out.args
        stage_meta.append({
            "stage": stage_name, "tool": out.tool, "ok": out.ok,
            "incomplete": out.incomplete, "duration_ms": out.duration_ms,
            "assets": len(out.assets), "observations": len(out.observations),
            "stderr_excerpt": out.stderr_excerpt[:500], "note": out.note,
        })
        incomplete = incomplete or out.incomplete or not out.ok
        for a in out.assets:
            if a.kind == "HOSTNAME" and a.value not in discovered_hosts:
                discovered_hosts.append(a.value)

    # --- persist results ------------------------------------------------
    with SessionLocal() as db:
        execution = db.get(ScanExecution, execution_id)
        if execution.state in {"CANCELLED", "TIMED_OUT", "FAILED"}:
            return execution.state

        execution.stages = stage_meta
        execution.tool_versions = tool_versions
        execution.normalized_args = normalized_args
        execution.parser_version = "2"

        try:
            summary = apply_stage_outputs(db, execution, stage_outputs)
        except Exception as exc:  # noqa: BLE001 - parser must not crash the worker
            db.rollback()
            execution = db.get(ScanExecution, execution_id)
            ScanService.transition(db, execution, "FAILED", actor="system:worker",
                                   reason=f"normalization error: {exc}")
            db.commit()
            return "FAILED"

        if execution.cancel_requested:
            ScanService.transition(db, execution, "CANCELLING", actor="system:worker",
                                   reason=execution.cancel_reason or "cancelled")
            execution.partial = True
            ScanService.transition(db, execution, "CANCELLED", actor="system:worker",
                                   extra_payload=summary)
            db.commit()
            return "CANCELLED"

        execution.partial = incomplete
        ScanService.transition(
            db, execution, "COMPLETED", actor="system:worker",
            extra_payload={**summary, "partial": incomplete},
        )
        AuditService.append(
            db, actor="system:worker", action="SCAN_RESULTS_NORMALIZED",
            object_type="scan_execution", object_id=execution.id,
            payload={**summary, "tool_versions": tool_versions,
                     "stages": [m["stage"] for m in stage_meta]},
        )
        db.commit()
        return "COMPLETED"


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
