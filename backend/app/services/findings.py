"""Finding normalization and stable fingerprints (PRD §15.2).

A fingerprint combines the logical target, the normalized asset identity, the
source tool, the rule/template id, protocol+port, and a stable evidence key.
Volatile values (timestamps, random response data, free-form text) never enter
the fingerprint.
"""
from __future__ import annotations

import datetime as dt
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, Finding, FindingSighting, ScanExecution

_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def fingerprint(*, target_id: str, asset_value: str, source_tool: str, rule_id: str,
                protocol: str, port: int | None, evidence_key: str) -> str:
    canonical = "\x1f".join([
        target_id,
        (asset_value or "").strip().lower(),
        source_tool,
        rule_id,
        protocol or "tcp",
        str(port or ""),
        (evidence_key or "").strip(),
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def severity_rank(sev: str) -> int:
    return _SEV_ORDER.get((sev or "INFO").upper(), 0)


def record_findings(db: Session, execution: ScanExecution, stage_outputs) -> dict:
    """Upsert findings + create one sighting per finding for this execution."""
    now = dt.datetime.now(dt.timezone.utc)
    target_id = execution.target_id
    new = still = changed = 0

    asset_by_value = {
        a.value: a.id
        for a in db.execute(select(Asset).where(Asset.target_id == target_id)).scalars()
    }
    # A tool can report the same indicator more than once in a run (e.g. once per
    # probed URL for the same host). Record exactly one sighting per finding.
    sighted: set[str] = set()

    for out in stage_outputs:
        for f in getattr(out, "findings", []):
            fp = fingerprint(
                target_id=target_id, asset_value=f.asset_value, source_tool=out.tool,
                rule_id=f.rule_id, protocol=f.protocol, port=f.port, evidence_key=f.evidence_key,
            )
            existing = db.execute(
                select(Finding).where(Finding.target_id == target_id, Finding.fingerprint == fp)
            ).scalar_one_or_none()

            if existing is None:
                finding = Finding(
                    target_id=target_id, asset_id=asset_by_value.get(f.asset_value),
                    fingerprint=fp, source_tool=out.tool, rule_id=f.rule_id,
                    template_hash=f.template_hash, severity=f.severity, name=f.name,
                    description=f.description, asset_value=f.asset_value, port=f.port,
                    protocol=f.protocol, matcher_name=f.matcher_name,
                    evidence_summary=f.evidence_summary, evidence=f.evidence or {},
                    status="OBSERVED", first_seen_at=now, last_seen_at=now,
                    first_execution_id=execution.id, last_execution_id=execution.id,
                )
                db.add(finding)
                db.flush()
                new += 1
            else:
                if existing.severity != f.severity or existing.evidence_summary != f.evidence_summary:
                    changed += 1
                else:
                    still += 1
                existing.severity = f.severity
                existing.name = f.name or existing.name
                existing.evidence_summary = f.evidence_summary
                existing.evidence = f.evidence or existing.evidence
                existing.status = "OBSERVED"
                existing.last_seen_at = now
                existing.last_execution_id = execution.id
                finding = existing

            if finding.id in sighted:
                continue
            sighted.add(finding.id)
            db.add(FindingSighting(
                finding_id=finding.id, execution_id=execution.id, severity=f.severity,
                evidence_key=f.evidence_key, seen_at=now,
            ))

    return {"findings_new": new, "findings_still": still, "findings_changed": changed}
