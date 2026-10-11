"""Restricted framework adapter contract + conservative interpretation (Phase 14).

All fake-backed: no real framework, no target contact. The contract tests pin
down the restricted surface (no generic exec/console), job-id correlation,
idempotency under lost acks / duplicate delivery, and that unsupported things
error rather than fall back. The interpretation tests pin §21.4.
"""
from __future__ import annotations

import pytest

from app.services.framework import (
    APPEARS,
    DETECTED,
    ERROR,
    EV_CANDIDATE,
    EV_CONDITION,
    EV_CONDITION_NEGATIVE,
    EV_INCONCLUSIVE,
    EV_PRODUCT_SERVICE,
    SAFE,
    UNKNOWN,
    VULNERABLE,
    CheckJob,
    FakeFrameworkAdapter,
    FrameworkAdapter,
    NativeResult,
    UnsupportedOperationError,
    get_framework_adapter,
    interpret_native_result,
)


def _adapter() -> FakeFrameworkAdapter:
    return FakeFrameworkAdapter(fixtures={
        "sample/mod-vuln": NativeResult(job_id="", native_code=VULNERABLE,
                                        service_reached=True, check_completed=True),
        "sample/mod-safe": NativeResult(job_id="", native_code=SAFE,
                                        service_reached=True, check_completed=True),
    })


# --- restricted surface ----------------------------------------------------


def test_no_generic_exploit_console_or_payload_operations():
    # the permitted surface is explicitly enumerated and excludes exec/console
    ops = set(get_framework_adapter().capabilities().operations)
    assert ops == {"capabilities", "module_metadata", "start_check", "job_status",
                   "job_result", "cancel"}
    for forbidden in ("execute", "exploit", "console", "payload_generate",
                      "datastore_set", "module_load", "run_resource_script"):
        assert not hasattr(FrameworkAdapter, forbidden)
        assert not hasattr(FakeFrameworkAdapter, forbidden)


def test_unsupported_module_raises_not_falls_back():
    a = _adapter()
    with pytest.raises(UnsupportedOperationError):
        a.module_metadata("sample/does-not-exist")
    with pytest.raises(UnsupportedOperationError):
        a.start_check(CheckJob(module_id="sample/does-not-exist", target="10.10.1.5"))


# --- job correlation + idempotency -----------------------------------------


def test_job_id_correlation():
    a = _adapter()
    job_id = a.start_check(CheckJob(module_id="sample/mod-vuln", target="10.10.1.5"))
    assert a.job_status(job_id).job_id == job_id
    assert a.job_result(job_id).native_code == VULNERABLE


def test_lost_ack_duplicate_submit_maps_to_one_job():
    a = _adapter()
    j1 = a.start_check(CheckJob(module_id="sample/mod-vuln", target="10.10.1.5", idempotency_key="k1"))
    j2 = a.start_check(CheckJob(module_id="sample/mod-vuln", target="10.10.1.5", idempotency_key="k1"))
    assert j1 == j2  # a retried/duplicated submit does not create a second job


def test_duplicate_result_delivery_is_idempotent():
    a = _adapter()
    job_id = a.start_check(CheckJob(module_id="sample/mod-safe", target="10.10.1.5"))
    assert a.job_result(job_id) == a.job_result(job_id)


def test_unknown_job_raises():
    a = _adapter()
    with pytest.raises(UnsupportedOperationError):
        a.job_result("job-999")


# --- conservative interpretation (§21.4) -----------------------------------


def test_verdict_mapping_never_means_demonstrated_impact():
    assert interpret_native_result(NativeResult("j", APPEARS))["evidence"] == EV_CANDIDATE
    assert interpret_native_result(NativeResult("j", DETECTED))["evidence"] == EV_PRODUCT_SERVICE
    cond = interpret_native_result(NativeResult("j", VULNERABLE))
    assert cond["evidence"] == EV_CONDITION
    assert cond["demonstrated"] is False  # a check verdict is not an executed exploit


def test_safe_is_conclusive_only_with_telemetry():
    with_telemetry = interpret_native_result(
        NativeResult("j", SAFE, service_reached=True, check_completed=True))
    assert with_telemetry["evidence"] == EV_CONDITION_NEGATIVE
    assert with_telemetry["establishes_absence"] is True

    without = interpret_native_result(
        NativeResult("j", SAFE, service_reached=False, check_completed=False))
    assert without["evidence"] == EV_INCONCLUSIVE
    assert without["establishes_absence"] is False


def test_unknown_and_error_do_not_establish_absence():
    for code in (UNKNOWN, ERROR, "", "Timeout"):
        out = interpret_native_result(NativeResult("j", code))
        assert out["evidence"] == EV_INCONCLUSIVE
        assert out["establishes_absence"] is False
