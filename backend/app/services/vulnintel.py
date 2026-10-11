"""Offline CVE intelligence and deterministic priority (PRD v2 §9/§11, Phase 11).

All intelligence comes from a **local, versioned snapshot file** — no scan ever
performs an online lookup, and no target identifier or evidence is ever
transmitted for enrichment (matching takes only product/version strings we
already hold). Matching is conservative: an auto-match stays ``CANDIDATE`` and
is never auto-promoted to ``SUPPORTED`` (an upstream version does not establish
patch state — vendor backports, distro revisions and banner masking all apply).
Candidates are stored separately from canonical issues so they cannot inflate
the actionable finding count.

Priority is expressed as a lane + reason codes (PRD v2 §11.1), never a synthetic
0–100 score. UNKNOWN context routes to validation, never silently to low risk.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import CandidateAssociation, Observation, ScanExecution, Service

APPLICABILITY_RULE_VERSION = "1"
PRIORITY_POLICY_VERSION = "v1"

# Applicability states (§9.1).
CANDIDATE = "CANDIDATE"
SUPPORTED = "SUPPORTED"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNKNOWN = "UNKNOWN"

# Test seam: inject a snapshot dict to avoid touching the filesystem.
_override: dict | None = None


def set_snapshot(snapshot: dict | None) -> None:
    global _override
    _override = snapshot


def load_snapshot() -> dict | None:
    if _override is not None:
        return _override
    path = get_settings().vulnintel_snapshot_path
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def snapshot_status() -> dict:
    """Freshness/availability of the local snapshot (§9.2). Missing/failed data
    is UNKNOWN, never treated as zero risk."""
    snap = load_snapshot()
    if not snap:
        return {"status": "MISSING", "provider": None, "effective_at": None,
                "schema_version": None, "record_count": 0, "stale": True}
    effective = str(snap.get("effective_at") or "")
    stale = True
    age_hours = None
    parsed = _parse_time(effective)
    if parsed is not None:
        age_hours = (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds() / 3600.0
        stale = age_hours > get_settings().vulnintel_stale_hours
    return {
        "status": "STALE" if stale else "FRESH",
        "provider": snap.get("provider"),
        "effective_at": effective or None,
        "schema_version": str(snap.get("schema_version") or ""),
        "record_count": len(snap.get("records") or []),
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "stale": stale,
    }


def _parse_time(value: str) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-_]", (v or "").strip())
    out: list[int] = []
    for p in parts:
        m = re.match(r"^\d+", p)
        out.append(int(m.group()) if m else 0)
    return tuple(out) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _in_range(version: str, start_incl: str, end_excl: str) -> bool:
    if start_incl and _cmp(version, start_incl) < 0:
        return False
    if end_excl and _cmp(version, end_excl) >= 0:
        return False
    return True


_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*)\s*/\s*([0-9][0-9A-Za-z.\-_]*)")


def extract_products(services, observations) -> list[tuple[str, str]]:
    """Pull (product, version) pairs from nmap service rows and httpx Server
    headers. Product-only (no version) yields a ("product", "") pair so the
    matcher can record an UNKNOWN candidate rather than silently dropping it."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(product: str, version: str) -> None:
        product = (product or "").strip().lower().split("/")[0]
        if not product:
            return
        key = (product, version)
        if key not in seen:
            seen.add(key)
            out.append(key)

    for s in services:
        if getattr(s, "product", ""):
            add(s.product, (getattr(s, "version", "") or ""))
    for o in observations:
        if o.kind == "HTTP_HEADER" and o.key == "Server" and o.value:
            m = _SERVER_RE.match(o.value.strip())
            if m:
                add(m.group(1), m.group(2))
            else:
                add(o.value.strip(), "")
    return out


def match_candidates(products: list[tuple[str, str]], snapshot: dict) -> list[dict]:
    """Conservatively match product/version pairs against snapshot records.

    Only CANDIDATE and UNKNOWN associations are returned: a version-in-range
    match is a CANDIDATE (patch state unverified), a product-only match is
    UNKNOWN, and a version outside the affected range is NOT_APPLICABLE and
    simply not stored (it would be noise). Never returns SUPPORTED — that
    requires reviewed evidence (Phase 12)."""
    records = (snapshot or {}).get("records") or []
    results: list[dict] = []
    for product, version in products:
        for rec in records:
            if str(rec.get("product", "")).strip().lower() != product:
                continue
            start = str(rec.get("version_start_incl") or "")
            end = str(rec.get("version_end_excl") or "")
            if not version:
                applicability, confidence, rationale = (
                    UNKNOWN, "LOW", "product matched, version unknown")
            elif _in_range(version, start, end):
                applicability, confidence, rationale = (
                    CANDIDATE, "LOW",
                    f"version {version} within affected range [{start or '0'}, {end or '∞'}); "
                    "patch/backport state unverified")
            else:
                continue  # NOT_APPLICABLE — not stored
            results.append({
                "cve_id": rec.get("cve", ""),
                "product": product,
                "version_evidence": version,
                "matched_cpe": rec.get("cpe", ""),
                "version_range": f"[{start or '0'}, {end or '∞'})",
                "applicability": applicability,
                "confidence": confidence,
                "cvss_version": str(rec.get("cvss_version") or ""),
                "cvss_score": rec.get("cvss_score"),
                "kev": bool(rec.get("kev")),
                "epss_score": rec.get("epss_score"),
                "epss_percentile": rec.get("epss_percentile"),
                "advisory_source": rec.get("advisory", ""),
                "match_rationale": rationale,
            })
    return results


def priority_lane(applicability: str, *, kev: bool, cvss_score: float | None,
                  epss_score: float | None, exposure: str = UNKNOWN,
                  criticality: str = UNKNOWN,
                  epss_threshold: float = 0.10) -> tuple[str, list[str]]:
    """Deterministic §11.1 lane + reason codes. Rows are evaluated in order and
    all triggered reasons retained. Missing intelligence never silently lowers
    risk — UNKNOWN routes to validation."""
    reasons: list[str] = []
    score = cvss_score or 0.0
    epss = epss_score or 0.0
    critical = score >= 9.0
    high = score >= 7.0
    medium = score >= 4.0
    internet = exposure == "INTERNET_EXPOSED"

    if applicability == CANDIDATE:
        if kev:
            reasons.append("candidate-cve-in-kev")
            return "VALIDATE_URGENT", reasons
        if critical and internet:
            reasons.append("candidate-critical-internet-exposed")
            return "VALIDATE_URGENT", reasons
        reasons.append("candidate-pending-applicability")
        return "VALIDATE", reasons

    if applicability == SUPPORTED:
        if critical or (kev and (internet or criticality == "HIGH")):
            reasons.append("supported-critical-or-kev-exposed")
            return "P1", reasons
        if high or kev or (medium and internet and epss >= epss_threshold):
            reasons.append("supported-high-or-kev-or-epss-exposed")
            return "P2", reasons
        if score > 0:
            reasons.append("supported-medium-low")
            return "P3", reasons
        reasons.append("informational")
        return "P4", reasons

    # UNKNOWN / anything else — never silently low.
    reasons.append("unknown-applicability-needs-review")
    return "VALIDATE", reasons


def derive_candidates(db: Session, execution: ScanExecution) -> dict:
    """Project candidate CVE associations for this execution's product/version
    evidence from the local snapshot. Offline and idempotent (upsert keyed on
    target+cve+product+version). Exposure/criticality are administrator-set per
    target (deferred); they default to UNKNOWN here and are never inferred from
    an RFC1918 address (§11)."""
    snap = load_snapshot()
    if not snap:
        return {"candidates": 0, "snapshot": "MISSING"}
    snap_version = f"{snap.get('provider', '')}@{snap.get('effective_at', '')}"

    services = db.execute(
        select(Service).where(Service.target_id == execution.target_id)
    ).scalars().all()
    observations = db.execute(
        select(Observation).where(Observation.execution_id == execution.id)
    ).scalars().all()

    products = extract_products(services, observations)
    n = 0
    for assoc in match_candidates(products, snap):
        lane, reasons = priority_lane(
            assoc["applicability"], kev=assoc["kev"], cvss_score=assoc["cvss_score"],
            epss_score=assoc["epss_score"],
        )
        existing = db.execute(
            select(CandidateAssociation).where(
                CandidateAssociation.target_id == execution.target_id,
                CandidateAssociation.cve_id == assoc["cve_id"],
                CandidateAssociation.product == assoc["product"],
                CandidateAssociation.version_evidence == assoc["version_evidence"],
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(CandidateAssociation(
                target_id=execution.target_id, applicability_rule_version=APPLICABILITY_RULE_VERSION,
                priority_lane=lane, priority_reasons=reasons, snapshot_version=snap_version,
                **assoc,
            ))
            n += 1
        else:
            existing.applicability = assoc["applicability"]
            existing.priority_lane = lane
            existing.priority_reasons = reasons
            existing.snapshot_version = snap_version
    return {"candidates": n, "snapshot": snap_version}


def backfill_candidates(db: Session) -> dict:
    """Re-derive candidate associations for every completed execution against the
    current snapshot (§9.2: a new snapshot may re-prioritize existing issues
    without a rescan). Offline and idempotent."""
    execs = db.execute(
        select(ScanExecution).where(ScanExecution.state == "COMPLETED")
        .order_by(ScanExecution.created_at)
    ).scalars().all()
    total = 0
    for ex in execs:
        total += derive_candidates(db, ex).get("candidates", 0)
    return {"candidates": total, "executions": len(execs), "snapshot": snapshot_status()}
