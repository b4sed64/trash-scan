"""Restricted framework (Metasploit) adapter — fake/metadata backend (PRD v2 §21.2, Phase 14).

This defines the *only* way the application may ever talk to the framework: a
narrow, typed operation surface — capabilities, module metadata, and admitted
check/job operations — and nothing else. There is deliberately **no** generic
RPC, console passthrough, arbitrary datastore options, payload generation,
module loading, resource scripts, or local-shell fallback. Those are not
"missing features" to add later; their absence is the contract.

In this phase the backend is a **fake** with sanitized native-response fixtures.
No real framework is contacted and nothing executes against a target. A real
adapter (private, authenticated RPC reachable only inside the restricted worker
boundary) is introduced later and remains withheld until the Phase 15 lab
isolation/recovery gates pass — a state-changing operation never runs before then.

``interpret_native_result`` encodes the conservative §21.4 mapping so a framework
verdict is never over-read: only ``Vulnerable`` maps to reviewed *condition*
evidence (never demonstrated impact), and ``Safe`` is a conclusive negative only
when telemetry proves the service was actually reached and the check completed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Native framework check verdicts (Metasploit's module check return values).
APPEARS = "Appears"
DETECTED = "Detected"
VULNERABLE = "Vulnerable"
SAFE = "Safe"
UNKNOWN = "Unknown"
UNSUPPORTED = "Unsupported"
ERROR = "Error"
TIMEOUT = "Timeout"

# Our conservative interpretation (§21.4). None of these mean demonstrated impact.
EV_CANDIDATE = "CANDIDATE"               # Appears — heuristic/version guess
EV_PRODUCT_SERVICE = "PRODUCT_SERVICE"   # Detected — product/service confirmed
EV_CONDITION = "CONDITION"               # Vulnerable — reviewed condition evidence
EV_CONDITION_NEGATIVE = "CONDITION_NEGATIVE"  # Safe + telemetry — conclusive negative
EV_INCONCLUSIVE = "INCONCLUSIVE"         # everything else / Safe without telemetry


class FrameworkError(Exception):
    """Base class for framework adapter errors."""


class UnsupportedOperationError(FrameworkError):
    """A method, module, or option that the pinned revision does not support.
    There is no console/generic-RPC fallback — unsupported is unavailable."""


class FrameworkRPCError(FrameworkError):
    """The framework returned a native error for a supported operation."""


@dataclass(frozen=True)
class FrameworkCapabilities:
    version: str
    module_ids: tuple[str, ...]
    supports_check: bool
    # Explicitly enumerated; anything not here is unsupported, not a fallback.
    operations: tuple[str, ...] = ("capabilities", "module_metadata", "start_check",
                                    "job_status", "job_result", "cancel")


@dataclass(frozen=True)
class CheckJob:
    module_id: str
    target: str            # pre-resolved in-scope lab fixture address
    options: dict = field(default_factory=dict)
    idempotency_key: str = ""   # lets a retried/duplicated submit map to one job


@dataclass(frozen=True)
class JobStatus:
    job_id: str
    state: str             # QUEUED | RUNNING | DONE | FAILED
    native_code: str = ""


@dataclass(frozen=True)
class NativeResult:
    job_id: str
    native_code: str       # one of the native verdicts above
    raw: dict = field(default_factory=dict)   # preserved raw framework outcome
    service_reached: bool = False
    check_completed: bool = False


@runtime_checkable
class FrameworkAdapter(Protocol):
    """The entire permitted surface. Note the absence of any exploit/console/
    payload/datastore/module-load operation — that is intentional."""

    def capabilities(self) -> FrameworkCapabilities: ...
    def module_metadata(self, module_id: str) -> dict: ...
    def start_check(self, job: CheckJob) -> str: ...
    def job_status(self, job_id: str) -> JobStatus: ...
    def job_result(self, job_id: str) -> NativeResult: ...
    def cancel(self, job_id: str) -> None: ...


def interpret_native_result(result: NativeResult) -> dict:
    """Map a native framework verdict to our conservative evidence class (§21.4).

    ``Safe`` only establishes a conclusive condition negative when telemetry
    proves the service was reached AND the check completed; otherwise, and for
    ``Unknown``/``Unsupported``/``Error``/``Timeout``/absent, the result is
    INCONCLUSIVE and never establishes absence or demonstrated impact.
    """
    code = result.native_code
    demonstrated = False  # a check verdict NEVER means an exploit was executed
    if code == APPEARS:
        return {"evidence": EV_CANDIDATE, "demonstrated": demonstrated,
                "establishes_absence": False, "native_code": code}
    if code == DETECTED:
        return {"evidence": EV_PRODUCT_SERVICE, "demonstrated": demonstrated,
                "establishes_absence": False, "native_code": code}
    if code == VULNERABLE:
        return {"evidence": EV_CONDITION, "demonstrated": demonstrated,
                "establishes_absence": False, "native_code": code}
    if code == SAFE:
        if result.service_reached and result.check_completed:
            return {"evidence": EV_CONDITION_NEGATIVE, "demonstrated": demonstrated,
                    "establishes_absence": True, "native_code": code}
        return {"evidence": EV_INCONCLUSIVE, "demonstrated": demonstrated,
                "establishes_absence": False, "native_code": code,
                "note": "Safe without telemetry that the service was reached — inconclusive"}
    # Unknown / Unsupported / Error / Timeout / anything absent.
    return {"evidence": EV_INCONCLUSIVE, "demonstrated": demonstrated,
            "establishes_absence": False, "native_code": code or "absent"}


class FakeFrameworkAdapter:
    """Deterministic fake backend with sanitized native-response fixtures. Used
    for all development and tests; contacts no real framework and no target."""

    def __init__(self, fixtures: dict[str, NativeResult] | None = None,
                 version: str = "fake-msf/0.0.0"):
        # module_id -> the native result a check would (fictionally) return
        self._fixtures = fixtures or {}
        self._version = version
        self._jobs: dict[str, NativeResult] = {}
        self._status: dict[str, str] = {}
        self._by_key: dict[str, str] = {}
        self._seq = 0

    def capabilities(self) -> FrameworkCapabilities:
        return FrameworkCapabilities(version=self._version,
                                     module_ids=tuple(self._fixtures),
                                     supports_check=True)

    def module_metadata(self, module_id: str) -> dict:
        if module_id not in self._fixtures:
            raise UnsupportedOperationError(f"module not supported: {module_id}")
        return {"module_id": module_id, "framework_version": self._version}

    def start_check(self, job: CheckJob) -> str:
        if job.module_id not in self._fixtures:
            raise UnsupportedOperationError(f"module not supported: {job.module_id}")
        # Idempotent on a client key so a lost ack / duplicate submit maps to one job.
        if job.idempotency_key and job.idempotency_key in self._by_key:
            return self._by_key[job.idempotency_key]
        self._seq += 1
        job_id = f"job-{self._seq}"
        native = self._fixtures[job.module_id]
        self._jobs[job_id] = NativeResult(job_id=job_id, native_code=native.native_code,
                                          raw=native.raw, service_reached=native.service_reached,
                                          check_completed=native.check_completed)
        self._status[job_id] = "DONE"
        if job.idempotency_key:
            self._by_key[job.idempotency_key] = job_id
        return job_id

    def job_status(self, job_id: str) -> JobStatus:
        if job_id not in self._status:
            raise UnsupportedOperationError(f"unknown job: {job_id}")
        r = self._jobs.get(job_id)
        return JobStatus(job_id=job_id, state=self._status[job_id],
                         native_code=r.native_code if r else "")

    def job_result(self, job_id: str) -> NativeResult:
        # Idempotent: duplicate delivery of the same job returns the same result.
        if job_id not in self._jobs:
            raise UnsupportedOperationError(f"unknown job: {job_id}")
        return self._jobs[job_id]

    def cancel(self, job_id: str) -> None:
        if job_id in self._status:
            self._status[job_id] = "FAILED"


def get_framework_adapter() -> FrameworkAdapter:
    """Return the active framework adapter. In this phase always the fake —
    there is no real backend yet, and a real one stays withheld until the Phase
    15 lab gates. There is intentionally no local-shell or console fallback."""
    return FakeFrameworkAdapter()
