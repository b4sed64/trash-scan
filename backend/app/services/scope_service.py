"""ScopeService — canonicalisation and scope-boundary enforcement.

This module is the security-critical core described in PRD sections 6 and 20. It
is deliberately free of database and framework imports so it can be unit-tested
in isolation with adversarial fixtures (PRD 27.1).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

import idna

# --- Target kinds -----------------------------------------------------------
KIND_IPV4 = "IPV4"
KIND_CIDR = "CIDR"
KIND_DOMAIN = "DOMAIN"

# --- Deny-rule types -------------------------------------------------------
DENY_DOMAIN_EXACT = "DOMAIN_EXACT"
DENY_DOMAIN_SUFFIX = "DOMAIN_SUFFIX"
DENY_IP = "IP"
DENY_CIDR = "CIDR"

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeError(ValueError):
    """Raised when a target cannot be parsed or violates policy."""


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------
def canonicalize_domain(raw: str, *, require_multilabel: bool = True) -> str:
    s = raw.strip().strip(".").lower()
    if not s or " " in s or "/" in s or "@" in s:
        raise ScopeError(f"invalid domain: {raw!r}")
    # Reject anything that is actually an IP literal.
    try:
        ipaddress.ip_address(s)
        raise ScopeError("expected a domain, got an IP literal")
    except ValueError:
        pass
    labels = s.split(".")
    try:
        # idna.encode normalises unicode and validates individual labels.
        labels = [idna.encode(label, uts46=True).decode("ascii") for label in labels]
        s = ".".join(labels)
    except idna.IDNAError as exc:  # pragma: no cover - exercised via tests
        raise ScopeError(f"invalid IDNA domain: {raw!r}") from exc
    if require_multilabel and len(labels) < 2:
        raise ScopeError("domain must have at least two labels")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ScopeError(f"invalid domain label: {label!r}")
    return s


def canonicalize_target(raw: str) -> tuple[str, str]:
    """Return ``(kind, canonical_value)`` for a user-supplied target.

    IPv6 is rejected (PRD non-goal). CIDR host bits are cleared.
    """
    if raw is None:
        raise ScopeError("empty target")
    s = raw.strip()
    if not s:
        raise ScopeError("empty target")

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise ScopeError(f"invalid CIDR: {raw!r}") from exc
        if net.version != 4:
            raise ScopeError("IPv6 is not supported in the MVP")
        return KIND_CIDR, str(net)

    try:
        ip = ipaddress.ip_address(s)
        if ip.version != 4:
            raise ScopeError("IPv6 is not supported in the MVP")
        return KIND_IPV4, str(ip)
    except ValueError:
        pass

    return KIND_DOMAIN, canonicalize_domain(s)


# ---------------------------------------------------------------------------
# Scope evaluation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DenyRuleSpec:
    rule_type: str
    value: str
    category: str = "CUSTOM"


@dataclass(frozen=True)
class PublicBoundary:
    """An approved, active public target the requester owns."""

    kind: str
    value: str


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    canonical_target: str
    resolved_addresses: list[str] = field(default_factory=list)
    matched_deny_rule: str | None = None

    def as_audit_payload(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "canonical_target": self.canonical_target,
            "resolved_addresses": sorted(self.resolved_addresses),
            "matched_deny_rule": self.matched_deny_rule,
        }


def _domain_denied(domain: str, rules: list[DenyRuleSpec]) -> DenyRuleSpec | None:
    for rule in rules:
        if rule.rule_type == DENY_DOMAIN_EXACT and domain == rule.value.lower().strip("."):
            return rule
        if rule.rule_type == DENY_DOMAIN_SUFFIX:
            suffix = rule.value.lower().lstrip(".").strip()
            if domain == suffix or domain.endswith("." + suffix):
                return rule
    return None


def _ip_denied(ip: str, rules: list[DenyRuleSpec]) -> DenyRuleSpec | None:
    addr = ipaddress.ip_address(ip)
    for rule in rules:
        try:
            if rule.rule_type == DENY_IP and addr == ipaddress.ip_address(rule.value):
                return rule
            if rule.rule_type == DENY_CIDR and addr in ipaddress.ip_network(rule.value, strict=False):
                return rule
        except ValueError:
            continue
    return None


def _within_any_cidr(ip: str, cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _within_public_boundary(
    kind: str, value: str, ip: str | None, boundaries: list[PublicBoundary]
) -> bool:
    for b in boundaries:
        if b.kind == KIND_DOMAIN and kind == KIND_DOMAIN:
            if value == b.value or value.endswith("." + b.value):
                return True
        if ip is not None and b.kind in (KIND_IPV4, KIND_CIDR):
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(b.value, strict=False):
                    return True
            except ValueError:
                continue
    return False


def evaluate_active_scope(
    kind: str,
    value: str,
    *,
    resolved_addresses: list[str] | None = None,
    private_cidrs: list[str],
    deny_rules: list[DenyRuleSpec],
    public_boundaries: list[PublicBoundary] | None = None,
) -> ScopeDecision:
    """Decide whether an active scan may target ``(kind, value)``.

    Rules (PRD 6.4):
      * Deny rules are applied first and can never be overridden.
      * Every address in play (the literal target and every resolved address)
        must fall inside an approved private CIDR or an approved public boundary.
      * A domain with no resolved addresses is ambiguous and is rejected
        (never send active traffic to an unresolved target).
    """
    resolved_addresses = list(resolved_addresses or [])
    public_boundaries = list(public_boundaries or [])
    decision = ScopeDecision(allowed=False, reason="", canonical_target=value,
                             resolved_addresses=resolved_addresses)

    # 1. Deny rules --------------------------------------------------------
    if kind == KIND_DOMAIN:
        hit = _domain_denied(value, deny_rules)
        if hit:
            decision.reason = f"target domain matches deny rule ({hit.category})"
            decision.matched_deny_rule = f"{hit.rule_type}:{hit.value}"
            return decision

    literal_ips: list[str] = []
    if kind == KIND_IPV4:
        literal_ips = [value]
    elif kind == KIND_CIDR:
        net = ipaddress.ip_network(value, strict=False)
        literal_ips = [str(net.network_address), str(net.broadcast_address)]

    for ip in literal_ips + resolved_addresses:
        hit = _ip_denied(ip, deny_rules)
        if hit:
            decision.reason = f"address {ip} matches deny rule ({hit.category})"
            decision.matched_deny_rule = f"{hit.rule_type}:{hit.value}"
            return decision

    # 2. Ambiguity -------------------------------------------------------
    if kind == KIND_DOMAIN and not resolved_addresses:
        decision.reason = "domain did not resolve; refusing to send active traffic to an ambiguous target"
        return decision

    # 3. Positive scope --------------------------------------------------
    if kind == KIND_CIDR:
        net = ipaddress.ip_network(value, strict=False)
        contained = any(
            net.subnet_of(ipaddress.ip_network(c, strict=False))
            for c in private_cidrs
            if ipaddress.ip_network(c, strict=False).version == 4
        )
        if not contained:
            decision.reason = "CIDR is not fully contained in an approved private range"
            return decision

    check_ips = literal_ips + resolved_addresses if kind != KIND_CIDR else resolved_addresses
    for ip in check_ips:
        if _within_any_cidr(ip, private_cidrs):
            continue
        if _within_public_boundary(kind, value, ip, public_boundaries):
            continue
        decision.reason = f"address {ip} is outside every approved private range and public boundary"
        return decision

    if kind == KIND_DOMAIN and not _within_public_boundary(kind, value, None, public_boundaries):
        # Domain resolved entirely into private space — allowed, but note it.
        pass

    decision.allowed = True
    decision.reason = "target and all resolved addresses are within approved scope"
    return decision


# ---------------------------------------------------------------------------
# Built-in prohibited-sector deny rules (PRD 6.3)
# ---------------------------------------------------------------------------
BUILTIN_DENY_RULES: list[DenyRuleSpec] = [
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "gov", "GOVERNMENT"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "mil", "MILITARY"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "gov.uk", "GOVERNMENT"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "mod.uk", "MILITARY"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "gov.au", "GOVERNMENT"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "gc.ca", "GOVERNMENT"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "nhs.uk", "HEALTHCARE"),
    DenyRuleSpec(DENY_DOMAIN_SUFFIX, "who.int", "HEALTHCARE"),
    DenyRuleSpec(DENY_DOMAIN_EXACT, "hhs.gov", "HEALTHCARE"),
    DenyRuleSpec(DENY_DOMAIN_EXACT, "cms.gov", "HEALTHCARE"),
]
