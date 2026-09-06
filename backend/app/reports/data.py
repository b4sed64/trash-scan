"""Assemble the data needed for a report (PRD §16.1)."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    Asset,
    Finding,
    Observation,
    PrivateCidr,
    ScanApproval,
    ScanComparison,
    ScanExecution,
    Service,
    Target,
    User,
)
from ..services.comparison import find_baseline

LIMITATIONS = [
    "This report is the result of automated, unauthenticated reconnaissance. Findings are "
    "indicators that require human validation, not proof of exploitability.",
    "A missing finding is reported as Not observed. It is never automatic evidence that an "
    "issue has been resolved.",
    "Docker Desktop / WSL networking, NAT and firewalls can affect reachability and the "
    "accuracy of OS detection. A missing response is not proof that an asset or service "
    "does not exist.",
    "Sector classification of prohibited (government / military / healthcare) organizations "
    "reduces risk but cannot guarantee identification of every such organization.",
    "The audit trail is tamper-evident, not tamper-proof.",
]

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _sev_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _executions(db: Session, target_id: str) -> list[ScanExecution]:
    return list(db.execute(
        select(ScanExecution).where(ScanExecution.target_id == target_id)
        .order_by(ScanExecution.created_at.desc())
    ).scalars())


def _authorization_block(db: Session, target: Target, executions: list[ScanExecution]) -> dict:
    block: dict = {"public_target": None, "latest_active_approval": None}
    if target.is_public:
        block["public_target"] = {
            "attestation": target.attestation_text,
            "attested_by": _username(db, target.attested_by_id),
            "attested_at": target.attested_at,
            "boundary": f"{target.kind} {target.value}",
        }
    active = next((e for e in executions if e.classification == "ACTIVE" and e.approval_id), None)
    if active:
        approval = db.get(ScanApproval, active.approval_id)
        if approval:
            block["latest_active_approval"] = {
                "approved_by": _username(db, approval.decided_by_id),
                "approved_at": approval.decided_at,
                "expires_at": approval.expires_at,
                "attestation_reference": f"approval {approval.id}",
                "attestation_text": approval.attestation_text,
                "approved_boundary": approval.scope_at_request.get("canonical_target")
                or f"{target.kind} {target.value}",
                "resolved_addresses": approval.scope_at_request.get("resolved_addresses", []),
                "profile": approval.profile,
            }
    return block


def _username(db: Session, user_id: str | None) -> str | None:
    if not user_id:
        return None
    u = db.get(User, user_id)
    return u.username if u else user_id


def gather_target_report(db: Session, target_id: str, *, requester: str) -> dict:
    target = db.get(Target, target_id)
    if target is None:
        raise ValueError("target not found")

    executions = _executions(db, target_id)
    latest = executions[0] if executions else None
    assets = list(db.execute(
        select(Asset).where(Asset.target_id == target_id).order_by(Asset.kind, Asset.value)
    ).scalars())
    services = list(db.execute(
        select(Service).where(Service.target_id == target_id).order_by(Service.asset_id, Service.port)
    ).scalars())
    observations = list(db.execute(
        select(Observation).where(Observation.target_id == target_id)
        .order_by(Observation.kind, Observation.key)
    ).scalars())
    findings = sorted(
        db.execute(select(Finding).where(Finding.target_id == target_id)).scalars(),
        key=lambda f: (_SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 99, f.rule_id),
    )

    comparison = None
    if latest:
        comparison = db.execute(
            select(ScanComparison).where(ScanComparison.execution_id == latest.id)
        ).scalar_one_or_none()
    baseline = find_baseline(db, latest) if latest else None

    settings = get_settings()
    tech_by_asset: dict[str, list[str]] = {}
    for o in observations:
        if o.kind == "TECH" and o.value:
            tech_by_asset.setdefault(o.asset_id or "", []).append(o.value)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc),
        "requester": requester,
        "brand": "Trash Scan",
        "target": {
            "value": target.value, "kind": target.kind,
            "is_public": target.is_public, "is_active": target.is_active, "note": target.note,
        },
        "scope": {
            "private_cidrs": [p.cidr for p in db.execute(select(PrivateCidr)).scalars()],
            "target_boundary": f"{target.kind} {target.value}",
        },
        "profiles_used": sorted({e.profile for e in executions}),
        "authorization": _authorization_block(db, target, executions),
        "summary": {
            "severity_counts": _sev_counts(findings),
            "comparison_counts": (comparison.summary.get("counts") if comparison
                                  and comparison.eligible else None),
            "asset_count": len(assets),
            "service_count": len(services),
            "finding_count": len(findings),
            "execution_count": len(executions),
        },
        "limitations": LIMITATIONS,
        "assets": [
            {
                "kind": a.kind, "value": a.value, "source": a.source,
                "in_scope": a.in_scope, "approved": a.approved,
                "ports": sorted(s.port for s in services if s.asset_id == a.id),
                "tech": tech_by_asset.get(a.id, []),
            }
            for a in assets
        ],
        "services": [
            {"asset_id": s.asset_id, "port": s.port, "protocol": s.protocol, "state": s.state,
             "product": s.product, "version": s.version, "confidence": s.confidence}
            for s in services
        ],
        "findings": [
            {
                "severity": f.severity, "name": f.name, "rule_id": f.rule_id,
                "source_tool": f.source_tool, "asset": f.asset_value, "port": f.port,
                "status": f.status, "evidence_summary": f.evidence_summary,
                "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at,
                "template_hash": f.template_hash,
            }
            for f in findings
        ],
        "comparison": {
            "eligible": bool(comparison and comparison.eligible),
            "baseline_execution_id": comparison.baseline_execution_id if comparison else None,
            "summary": comparison.summary if comparison else {},
            "limitations": comparison.limitations if comparison else [],
            "details": comparison.details if comparison else [],
        },
        "methodology": {
            "executions": [
                {
                    "id": e.id, "profile": e.profile, "state": e.state,
                    "started_at": e.started_at, "finished_at": e.finished_at,
                    "partial": e.partial, "tool_versions": e.tool_versions,
                    "template_set_hash": e.template_set_hash,
                    "normalized_args": e.normalized_args,
                    "stages": e.stages, "error": e.error,
                }
                for e in executions
            ],
            "limits": {
                "max_runtime_minutes": settings.max_runtime_minutes,
                "approval_window_minutes": settings.approval_window_minutes,
                "dns_qps": settings.dns_queries_per_second,
                "http_rps": settings.http_requests_per_second,
                "nuclei_rps": settings.nuclei_requests_per_second,
                "max_response_bytes": settings.max_response_bytes,
                "allow_raw_packet": settings.allow_raw_packet,
            },
        },
        "baseline_execution_id": baseline.id if baseline else None,
    }


def gather_execution_report(db: Session, execution_id: str, *, requester: str) -> dict:
    ex = db.get(ScanExecution, execution_id)
    if ex is None:
        raise ValueError("execution not found")
    ctx = gather_target_report(db, ex.target_id, requester=requester)
    ctx["scope"]["execution_id"] = execution_id
    ctx["single_execution"] = execution_id
    ctx["methodology"]["executions"] = [
        e for e in ctx["methodology"]["executions"] if e["id"] == execution_id
    ]
    return ctx
