"""Safe subprocess invocation for scanner tools (PRD §13).

Rules enforced here:
  * fixed executable path, argument *array*, never ``shell=True``;
  * the child runs in its own process group so the whole tree can be killed;
  * stdout/stderr are read with a hard byte cap;
  * a timeout terminates the complete process group (SIGTERM then SIGKILL).
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass


@dataclass
class ProcResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration_ms: int


class ToolNotFound(RuntimeError):
    pass


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:  # pragma: no cover - dev only
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _hard_kill_group(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run_tool(
    argv: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int = 4_000_000,
    cwd: str | None = None,
    stdin_data: bytes | None = None,
    grace_seconds: int = 5,
    should_cancel=None,
) -> ProcResult:
    """Run ``argv`` and return bounded output.

    ``should_cancel`` is an optional callable polled roughly once a second; when
    it returns True the process group is terminated just like a timeout.
    """
    if not argv or not argv[0]:
        raise ValueError("empty argv")

    start = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": "/tmp"},
        )
    except FileNotFoundError as exc:
        raise ToolNotFound(f"executable not found: {argv[0]}") from exc

    if stdin_data is not None:
        try:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    timed_out = False
    deadline = start + timeout_seconds
    # Poll so we can honour cancellation and the timeout without threads.
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline or (should_cancel is not None and should_cancel()):
            timed_out = now >= deadline
            _kill_group(proc)
            try:
                proc.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                _hard_kill_group(proc)
            break
        time.sleep(0.25)

    try:
        out, err = proc.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        _hard_kill_group(proc)
        out, err = proc.communicate()

    return ProcResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=(out or b"")[:max_output_bytes],
        stderr=(err or b"")[:max_output_bytes],
        timed_out=timed_out,
        duration_ms=int((time.monotonic() - start) * 1000),
    )


def excerpt(data: bytes, limit: int = 2000) -> str:
    text = data.decode("utf-8", errors="replace")
    return text if len(text) <= limit else text[:limit] + "\n…(truncated)"


def tool_version(binary: str, flag: str = "-version") -> str:
    """Best-effort version string for a CLI tool; never raises."""
    import shutil

    if not shutil.which(binary):
        return "unavailable"
    try:
        res = run_tool([binary, flag], timeout_seconds=15)
    except ToolNotFound:
        return "unavailable"
    import re

    blob = (res.stdout + b"\n" + res.stderr).decode("utf-8", errors="replace")
    semver = re.compile(r"v?\d+\.\d+\.\d+")
    for line in blob.splitlines():
        line = line.strip()
        if "version" in line.lower() and semver.search(line):
            return line[:120]
    for line in blob.splitlines():
        m = semver.search(line)
        if m:
            return m.group(0)
    return "unknown"
