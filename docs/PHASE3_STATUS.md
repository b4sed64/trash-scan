# Phase 3 status — Active workflow

## Deliverables (PRD §25, Phase 3)

| Deliverable | Status | Where |
|---|---|---|
| Attestation form | Done | `POST /api/targets/{id}/scans` with `profile` + exact `attestation_text`; frontend target detail |
| Administrator approval queue + notifications | Done | `app/api/approvals.py`, `Approvals` page, `APPROVAL_PENDING` notifications |
| Celery execution lifecycle | Done | `app/worker/runner.py` (passive + active), `app/services/execution_service.py` |
| Nmap + httpx adapters | Done (real, checksum/version pinned) | `app/adapters/nmap.py`, `app/adapters/httpx.py` |
| Safe / Standard profiles | Done | `app/scan_profiles.py` — UI option → fixed argument allowlist |
| Cancellation, emergency stop, rate/concurrency, approval expiry, runtime cap | Done | see below |

**Exit condition — active lifecycle and process termination pass end-to-end tests:**
`tests/test_active_workflow.py` (6 adversarial cases) + `tests/test_approvals_api.py`.
61 backend tests pass.

## Active execution workflow (PRD §8.1)

1. Requester `POST`s an active scan with the **exact** ethical-use attestation string
   (`app/constants.py::ACTIVE_SCAN_ATTESTATION`). A wrong string is a 422.
2. The backend re-evaluates scope now, rejects deny-rule matches and out-of-scope targets,
   then creates a `ScanExecution` in `AWAITING_APPROVAL` and a `ScanApproval` that snapshots
   the scope decision. All administrators get a dashboard notification.
3. An administrator approves or denies from `/api/approvals`. Approval sets
   `approval_expires_at = now + 2h`, moves the execution `APPROVED → QUEUED`, and enqueues it.
4. **Before the first tool runs**, the worker re-resolves the target and re-evaluates scope
   (`SCAN_SCOPE_RECHECK_PASSED` / `SCAN_SCOPE_RECHECK_FAILED` audit events). A domain that
   now resolves outside approved scope, or a deny match, ends the execution `FAILED` with no
   traffic sent.
5. `AWAITING_APPROVAL`/`APPROVED`/`QUEUED` past `approval_expires_at` → `EXPIRED`
   (`lifecycle_sweep` + a guard in the worker). An approval is single-use; re-approving is a
   409 and a completed execution is not re-runnable.
6. Runtime cap: `runtime_deadline_at = RUNNING + 2h`. The worker's cancel/deadline guard is
   polled ~1/s and passed into every tool; `lifecycle_sweep` marks a stuck `RUNNING`
   execution `TIMED_OUT`. Approval expiry and runtime cap are independent values.

## Profiles → argument allowlist (PRD §13, §22)

| Profile | Stages | Nmap |
|---|---|---|
| `SAFE_ACTIVE` | dnsx → nmap → httpx | `-sT` on the admin "safe" port set, `-sV --version-intensity 2`, `-Pn -n -T2` |
| `STANDARD_ACTIVE` | dnsx → nmap → httpx | broader port set, `-sV`, `-T3`; `-sS` and `-O` **only** when `TRASHSCAN_ALLOW_RAW_PACKET=1` |

- No raw flags, NSE scripts, decoys, spoofing, or fragmentation are reachable. Ports and
  timing come from config; rate comes from a two-value allowlist (`CONSERVATIVE`/`MODERATE`).
- httpx does **not** follow redirects by default — the `Location` header is captured and
  scope-checked, and flagged in the observation if it points outside approved scope.
- httpx is installed as `httpx-pd` to avoid clashing with the Python `httpx` CLI (PRD §12.4).

## Cancellation & emergency stop (PRD §23)

- `POST /api/scans/{id}/cancel` — a scanner cancels their own, an admin any. Not-yet-running
  executions resolve immediately; a running scan is stopped between stages and by killing the
  tool process group (`start_new_session` + SIGTERM→SIGKILL in `app/adapters/_exec.py`).
  Partial results are kept and `partial` is set.
- `POST /api/emergency-stop` (admin) — signals every non-terminal execution, blocks new
  starts (worker and scheduler check `emergency.active_stop`), and moves `REQUESTED →
  CONFIRMED` once everything signalled is terminal. `…/clear` lifts it. State is shown on the
  Scans page.

## Scheduled active scans (PRD §8.2)

`scheduler_tick` creates an `AWAITING_APPROVAL` execution + `ScanApproval` (linked to the
occurrence) for each due active occurrence and notifies admins — it never auto-runs. If the
schedule's attestation-relevant fields changed since the stored `options_hash`, the
occurrence is `DENIED` with `SCHEDULE_ATTESTATION_INVALIDATED`. A missed window is `EXPIRED`.

## New requirements coverage

| ID | Status | Note |
|---|---|---|
| SCAN-01 | Done | Passive, Safe active, Standard active |
| SCAN-02 | Done | typed attestation + fresh approval per execution |
| SCAN-03 | Done | unused approval expires at 2h; single-use |
| SCAN-04 | Done | runtime cap from `RUNNING`, independent of approval |
| SCAN-05 | Done | scanner cancels own, admin cancels any; admin emergency-stop |
| SCAN-06 | Done | process-group kill, downstream stages stopped, partial kept, reason audited |
| SCAN-07 | Done | every scheduled active occurrence pauses for approval |
| SCAN-08 | Done | global + per-target concurrency gate before `RUNNING`; per-tool rates |
| SCAN-09 | Partial | one controlled retry (`retry_max`); retry never extends the runtime deadline. Full backoff tuning deferred |
| SCAN-10 | Done | tool versions, normalized args, parser version, profile recorded per execution |
| SCOPE-03 / SCOPE-07 | Done | re-resolve + re-evaluate immediately before launch; deny/scope reject before any tool |
| NOTIF-02 / NOTIF-03 | Done | pending approvals surfaced to admins; requester notified on every terminal state |
| NFR-02 | Done | submit/approve/cancel/emergency-stop are single synchronous DB writes |

## Deferred / known limitations

- **SYN scan & OS detection are off** (`TRASHSCAN_ALLOW_RAW_PACKET=false`, no `NET_RAW`
  capability on the worker). Turning them on needs the PRD §0 spike to prove the minimum
  Docker capability; then add `cap_add: [NET_RAW]` to the `worker` service and set the flag.
- Nmap is installed from Debian bookworm (`7.93`) rather than a checksum-pinned tarball;
  reproducibility rests on the pinned base image. httpx/subfinder/dnsx are checksum-pinned.
- Redirect revalidation is "capture and flag", not "follow after re-check" — following is
  disabled entirely, which is the conservative reading of PRD §12.4.
- No transactional outbox yet; `lifecycle_sweep` re-queues anything stuck in `QUEUED`.
- Nuclei (Phase 4), findings/fingerprints/comparison (Phase 4), PDF/CSV reports (Phase 5)
  are not in this phase.
