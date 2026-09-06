"""Bridge between persisted scope configuration and the pure ScopeService."""
from __future__ import annotations

import socket

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import DenyRule, PrivateCidr, Target
from .scope_service import (
    KIND_CIDR,
    KIND_DOMAIN,
    KIND_IPV4,
    DenyRuleSpec,
    PublicBoundary,
    ScopeDecision,
    evaluate_active_scope,
)

# Injectable resolver so tests never touch the network.
_resolver = None


def set_resolver(func) -> None:
    global _resolver
    _resolver = func


def resolve_domain(domain: str) -> list[str]:
    if _resolver is not None:
        return list(_resolver(domain))
    if not get_settings().enable_dns_resolution:
        return []
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def load_deny_rules(db: Session) -> list[DenyRuleSpec]:
    rows = db.execute(select(DenyRule)).scalars().all()
    return [DenyRuleSpec(r.rule_type, r.value, r.category) for r in rows]


def load_private_cidrs(db: Session) -> list[str]:
    return list(db.execute(select(PrivateCidr.cidr)).scalars())


def load_public_boundaries(db: Session) -> list[PublicBoundary]:
    rows = db.execute(
        select(Target).where(Target.is_public.is_(True), Target.is_active.is_(True))
    ).scalars().all()
    return [PublicBoundary(t.kind, t.value) for t in rows]


def evaluate_target_scope(db: Session, target: Target) -> ScopeDecision:
    resolved: list[str] = []
    if target.kind == KIND_DOMAIN:
        resolved = resolve_domain(target.value)
    return evaluate_active_scope(
        target.kind,
        target.value,
        resolved_addresses=resolved,
        private_cidrs=load_private_cidrs(db),
        deny_rules=load_deny_rules(db),
        public_boundaries=load_public_boundaries(db),
    )
