"""Adversarial unit tests for canonicalisation and scope enforcement (PRD 27.1)."""
from __future__ import annotations

import pytest

from app.services.scope_service import (
    BUILTIN_DENY_RULES,
    DenyRuleSpec,
    PublicBoundary,
    ScopeError,
    canonicalize_target,
    evaluate_active_scope,
)

PRIVATE = ["10.10.0.0/16", "192.168.0.0/24"]


# --- canonicalisation --------------------------------------------------
@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("10.10.5.20", "IPV4", "10.10.5.20"),
        ("10.10.0.0/16", "CIDR", "10.10.0.0/16"),
        ("10.10.5.20/16", "CIDR", "10.10.0.0/16"),  # host bits cleared
        ("Example.COM", "DOMAIN", "example.com"),
        ("sub.example.com.", "DOMAIN", "sub.example.com"),
    ],
)
def test_canonicalize(raw, kind, value):
    if kind == "DOMAIN" and value is None:
        with pytest.raises(ScopeError):
            canonicalize_target(raw)
        return
    k, v = canonicalize_target(raw)
    assert (k, v) == (kind, value)


@pytest.mark.parametrize("raw", ["", "   ", "::1", "2001:db8::1", "fe80::1/64", "not a host", "a_b.com"])
def test_canonicalize_rejects(raw):
    with pytest.raises(ScopeError):
        canonicalize_target(raw)


# --- deny precedence -------------------------------------------------
def test_deny_beats_allow_for_ip():
    decision = evaluate_active_scope(
        "IPV4", "10.10.5.20",
        private_cidrs=PRIVATE,
        deny_rules=[DenyRuleSpec("IP", "10.10.5.20", "CUSTOM")],
    )
    assert not decision.allowed
    assert decision.matched_deny_rule == "IP:10.10.5.20"


def test_deny_cidr_inside_allowed_range():
    decision = evaluate_active_scope(
        "IPV4", "10.10.9.9",
        private_cidrs=PRIVATE,
        deny_rules=[DenyRuleSpec("CIDR", "10.10.9.0/24", "CUSTOM")],
    )
    assert not decision.allowed


@pytest.mark.parametrize("domain", ["army.mil", "sub.army.mil", "whitehouse.gov", "trust.nhs.uk"])
def test_builtin_sector_denylist(domain):
    decision = evaluate_active_scope(
        "DOMAIN", domain,
        resolved_addresses=["10.10.1.1"],
        private_cidrs=PRIVATE,
        deny_rules=list(BUILTIN_DENY_RULES),
    )
    assert not decision.allowed
    assert decision.matched_deny_rule is not None


# --- positive scope + ambiguity -----------------------------------
def test_ip_in_range_allowed():
    decision = evaluate_active_scope(
        "IPV4", "10.10.5.20", private_cidrs=PRIVATE, deny_rules=[]
    )
    assert decision.allowed


def test_ip_outside_range_denied():
    decision = evaluate_active_scope(
        "IPV4", "8.8.8.8", private_cidrs=PRIVATE, deny_rules=[]
    )
    assert not decision.allowed


def test_unresolved_domain_is_ambiguous():
    decision = evaluate_active_scope(
        "DOMAIN", "lab.example.com", resolved_addresses=[], private_cidrs=PRIVATE, deny_rules=[]
    )
    assert not decision.allowed
    assert "ambiguous" in decision.reason


def test_dns_rebinding_split_answer_denied():
    """One private + one public address must fail (PRD 6.4 rule 5)."""
    decision = evaluate_active_scope(
        "DOMAIN", "lab.example.com",
        resolved_addresses=["10.10.1.5", "203.0.113.7"],
        private_cidrs=PRIVATE, deny_rules=[],
    )
    assert not decision.allowed
    assert "203.0.113.7" in decision.reason


def test_domain_resolving_into_private_allowed():
    decision = evaluate_active_scope(
        "DOMAIN", "lab.example.com",
        resolved_addresses=["10.10.1.5", "192.168.0.9"],
        private_cidrs=PRIVATE, deny_rules=[],
    )
    assert decision.allowed


def test_cidr_must_be_fully_contained():
    assert not evaluate_active_scope(
        "CIDR", "10.0.0.0/8", private_cidrs=PRIVATE, deny_rules=[]
    ).allowed
    assert evaluate_active_scope(
        "CIDR", "10.10.5.0/24", private_cidrs=PRIVATE, deny_rules=[]
    ).allowed


def test_public_boundary_allows_owned_public_target():
    decision = evaluate_active_scope(
        "DOMAIN", "shop.team-owned.com",
        resolved_addresses=["203.0.113.10"],
        private_cidrs=PRIVATE,
        deny_rules=[],
        public_boundaries=[PublicBoundary("DOMAIN", "shop.team-owned.com")],
    )
    assert decision.allowed


def test_public_boundary_does_not_cover_siblings():
    decision = evaluate_active_scope(
        "DOMAIN", "evil.team-owned.com",
        resolved_addresses=["203.0.113.10"],
        private_cidrs=PRIVATE,
        deny_rules=[],
        public_boundaries=[PublicBoundary("DOMAIN", "shop.team-owned.com")],
    )
    assert not decision.allowed
