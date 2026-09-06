"""Normalize adapter output into Assets and Observations (FIND-01).

Discovered assets are always stored unapproved and never inherit target
authorization (SCOPE-04). Raw tool output stays on disk; only bounded, escaped
values are persisted.
"""
from __future__ import annotations

import datetime as dt
import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Asset, Observation, ScanExecution, Service
from .scope_db import load_private_cidrs


def _within_any_cidr(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _clean(value: str) -> str:
    limit = get_settings().max_evidence_bytes
    value = value.replace("\x00", "").strip()
    return value[:limit]


def apply_stage_outputs(db: Session, execution: ScanExecution, stage_outputs) -> dict:
    """Upsert assets/observations for a completed execution. Returns a summary."""
    target_id = execution.target_id
    now = dt.datetime.now(dt.timezone.utc)
    private_cidrs = load_private_cidrs(db)

    assets_added = assets_updated = obs_added = obs_updated = 0
    asset_ids: dict[tuple[str, str], str] = {}

    def upsert_asset(kind: str, value: str, source: str) -> str:
        nonlocal assets_added, assets_updated
        key = (kind, value)
        if key in asset_ids:
            return asset_ids[key]
        existing = db.execute(
            select(Asset).where(
                Asset.target_id == target_id, Asset.kind == kind, Asset.value == value
            )
        ).scalar_one_or_none()
        in_scope = kind == "IP" and _within_any_cidr(value, private_cidrs)
        if existing:
            existing.last_seen_at = now
            if kind == "IP":
                existing.in_scope = in_scope
            assets_updated += 1
            asset_ids[key] = existing.id
            return existing.id
        row = Asset(
            target_id=target_id, kind=kind, value=value, source=source,
            in_scope=in_scope, approved=False, first_seen_at=now, last_seen_at=now,
        )
        db.add(row)
        db.flush()
        assets_added += 1
        asset_ids[key] = row.id
        return row.id

    for out in stage_outputs:
        for disc in out.assets:
            upsert_asset(disc.kind, _clean(disc.value), disc.source)

    services_added = services_updated = 0
    for out in stage_outputs:
        for svc in getattr(out, "services", []):
            asset_id = upsert_asset("IP", _clean(svc.asset_value), out.tool)
            existing = db.execute(
                select(Service).where(
                    Service.target_id == target_id, Service.asset_id == asset_id,
                    Service.port == svc.port, Service.protocol == svc.protocol,
                )
            ).scalar_one_or_none()
            if existing:
                existing.last_seen_at = now
                existing.state = svc.state
                existing.product = _clean(svc.product)
                existing.version = _clean(svc.version)
                existing.confidence = svc.confidence
                services_updated += 1
            else:
                db.add(Service(
                    target_id=target_id, asset_id=asset_id, execution_id=execution.id,
                    port=svc.port, protocol=svc.protocol, state=svc.state,
                    product=_clean(svc.product), version=_clean(svc.version),
                    confidence=svc.confidence, first_seen_at=now, last_seen_at=now,
                ))
                services_added += 1

    seen_obs: set[tuple[str, str, str]] = set()
    for out in stage_outputs:
        for obs in out.observations:
            linked_asset_id = None
            if obs.asset_value:
                kind = "IP" if _looks_ip(obs.asset_value) else "HOSTNAME"
                linked_asset_id = asset_ids.get((kind, obs.asset_value))
            value = _clean(obs.value)
            dedup_key = (obs.kind, obs.key, value)
            if dedup_key in seen_obs:
                continue
            seen_obs.add(dedup_key)
            existing = db.execute(
                select(Observation).where(
                    Observation.target_id == target_id,
                    Observation.kind == obs.kind,
                    Observation.key == obs.key,
                    Observation.value == value,
                )
            ).scalar_one_or_none()
            if existing:
                existing.last_seen_at = now
                existing.execution_id = execution.id
                if linked_asset_id:
                    existing.asset_id = linked_asset_id
                obs_updated += 1
            else:
                db.add(Observation(
                    target_id=target_id, asset_id=linked_asset_id, execution_id=execution.id,
                    kind=obs.kind, key=obs.key, value=value, source_tool=obs.source,
                    first_seen_at=now, last_seen_at=now,
                ))
                obs_added += 1

    return {
        "assets_added": assets_added,
        "assets_updated": assets_updated,
        "services_added": services_added,
        "services_updated": services_updated,
        "observations_added": obs_added,
        "observations_updated": obs_updated,
    }


def _looks_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False
