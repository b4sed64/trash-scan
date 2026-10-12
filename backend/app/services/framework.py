"""Restricted framework (Metasploit) adapter — fake/metadata backend (PRD v2 §21.2, Phase 14).

This defines the *only* way the application may ever talk to the framework: a
narrow, typed operation surface — capabilities, module metadata, and admitted
check/job operations — and nothing else. There is deliberately **no** generic
RPC, console passthrough, arbitrary datastore options, payload generation,
module loading, resource scripts, or local-shell fallback. Those are not
"missing features" to add later; their absence is the contract.

The default backend is a **fake** with sanitized native-response fixtures: no
real framework is contacted and nothing executes. It is the only backend used
offline and in tests.

PRD v2 Phase 24 **widens this surface, by explicit administrator decision**, to
add authorized exploitation against an isolated lab: ``run_exploit`` /
``session_run`` / ``session_stop``, served by ``RealMetasploitAdapter`` (private
``msfrpcd`` RPC) when ``framework_mode=real``. This is the capability the earlier
phases deliberately withheld; it is additionally gated by ``enable_lab_proof``,
verified lab isolation and a registered fixture — the mode alone runs nothing —
and there is still no generic console/datastore/module-load passthrough.

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


@dataclass(frozen=True)
class ExploitJob:
    """A single, bounded exploit run against a pre-resolved in-scope lab fixture
    (PRD v2 Phase 24). ``marker`` is the benign token a follow-up command echoes
    to prove code execution; ``payload`` names the one admitted payload."""
    module_id: str
    target: str            # resolved lab fixture address (RHOSTS)
    options: dict = field(default_factory=dict)
    payload: str = ""
    marker: str = ""
    idempotency_key: str = ""


@dataclass(frozen=True)
class ExploitSession:
    """The outcome of an exploit run: whether a session opened, and its id. A
    closed/absent session (``opened=False``) is the expected result against a
    patched or non-vulnerable target."""
    session_id: str | None
    opened: bool
    module_id: str
    native: dict = field(default_factory=dict)


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
    # Phase 24 exploitation surface (gated; see module docstring).
    def run_exploit(self, job: ExploitJob) -> ExploitSession: ...
    def session_run(self, session_id: str, command: str, timeout_s: int = 15) -> str: ...
    def session_stop(self, session_id: str) -> None: ...


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
                 version: str = "fake-msf/0.0.0",
                 exploitable: dict[str, bool] | None = None):
        # module_id -> the native result a check would (fictionally) return
        self._fixtures = fixtures or {}
        self._version = version
        # module_id -> whether an exploit run (fictionally) opens a session.
        self._exploitable = exploitable or {}
        self._jobs: dict[str, NativeResult] = {}
        self._status: dict[str, str] = {}
        self._by_key: dict[str, str] = {}
        self._sessions: dict[str, bool] = {}   # session_id -> open?
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

    # --- Phase 24 exploitation surface (fake) ------------------------------

    def run_exploit(self, job: ExploitJob) -> ExploitSession:
        """Fictionally run an exploit. Opens a session only when the module is
        marked exploitable in the fixtures; against anything else (e.g. a patched
        target) no session opens — the expected negative-control outcome."""
        if job.idempotency_key and job.idempotency_key in self._by_key:
            sid = self._by_key[job.idempotency_key]
            return ExploitSession(session_id=sid, opened=self._sessions.get(sid, False),
                                  module_id=job.module_id)
        if not self._exploitable.get(job.module_id, False):
            return ExploitSession(session_id=None, opened=False, module_id=job.module_id,
                                  native={"note": "no session (target not vulnerable or patched)"})
        self._seq += 1
        sid = f"sess-{self._seq}"
        self._sessions[sid] = True
        if job.idempotency_key:
            self._by_key[job.idempotency_key] = sid
        return ExploitSession(session_id=sid, opened=True, module_id=job.module_id)

    def session_run(self, session_id: str, command: str, timeout_s: int = 15) -> str:
        if not self._sessions.get(session_id):
            raise FrameworkRPCError(f"session not open: {session_id}")
        # Simulate a shell: echo returns its argument; otherwise a canned id line.
        if command.startswith("echo "):
            return command[len("echo "):] + "\n"
        return "uid=0(root) gid=0(root)\n"

    def session_stop(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id] = False


class RealMetasploitAdapter:
    """Live ``msfrpcd`` backend for authorized isolated-lab exploitation (PRD v2
    Phase 24). Used only when ``framework_mode=real``; never reached offline or in
    tests. Still exposes no generic console/datastore passthrough — only the
    enumerated exploit/session operations."""

    def __init__(self, host: str, port: int, password: str, ssl: bool):
        from pymetasploit3.msfrpc import MsfRpcClient  # lazy: only needed live
        if not password:
            raise FrameworkError("msf_rpc_password is not set (TRASHSCAN_MSF_RPC_PASSWORD)")
        self._client = MsfRpcClient(password, server=host, port=port, ssl=ssl)

    def capabilities(self) -> FrameworkCapabilities:
        return FrameworkCapabilities(version=str(self._client.core.version.get("version", "msf")),
                                     module_ids=(), supports_check=True)

    def module_metadata(self, module_id: str) -> dict:
        return {"module_id": module_id}

    # Check operations are not enabled for the real backend in this work unit;
    # the admitted exploit path below is the only live operation.
    def start_check(self, job: CheckJob) -> str:
        raise UnsupportedOperationError("real adapter: module checks are not enabled")

    def job_status(self, job_id: str) -> JobStatus:
        raise UnsupportedOperationError("real adapter: checks are not enabled")

    def job_result(self, job_id: str) -> NativeResult:
        raise UnsupportedOperationError("real adapter: checks are not enabled")

    def cancel(self, job_id: str) -> None:
        raise UnsupportedOperationError("real adapter: checks are not enabled")

    def run_exploit(self, job: ExploitJob) -> ExploitSession:
        import time
        name = job.module_id.split("exploit/", 1)[-1]
        mod = self._client.modules.use("exploit", name)
        mod["RHOSTS"] = job.target
        for key, value in (job.options or {}).items():
            mod[key] = value
        before = set(self._client.sessions.list.keys())
        mod.execute(payload=job.payload) if job.payload else mod.execute()
        deadline = time.time() + 30
        sid = None
        while time.time() < deadline:
            new = set(self._client.sessions.list.keys()) - before
            if new:
                sid = str(sorted(new, key=str)[-1])
                break
            time.sleep(1)
        return ExploitSession(session_id=sid, opened=sid is not None, module_id=job.module_id)

    def session_run(self, session_id: str, command: str, timeout_s: int = 15) -> str:
        import time
        sess = self._client.sessions.session(session_id)
        sess.write(command + "\n")
        time.sleep(min(timeout_s, 5))
        out = sess.read() or ""
        return out

    def session_stop(self, session_id: str) -> None:
        try:
            self._client.sessions.session(session_id).stop()
        except Exception:  # noqa: BLE001 - best-effort cleanup; recovery is separate
            pass


def get_framework_adapter() -> FrameworkAdapter:
    """Return the active framework adapter. ``framework_mode=real`` returns the
    live ``msfrpcd`` backend (only reached once a gated proof actually executes);
    otherwise the fake. There is intentionally no console/datastore passthrough."""
    from ..config import get_settings
    settings = get_settings()
    if settings.framework_mode == "real":
        return RealMetasploitAdapter(settings.msf_rpc_host, settings.msf_rpc_port,
                                     settings.msf_rpc_password, settings.msf_rpc_ssl)
    return FakeFrameworkAdapter()
