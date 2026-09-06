# Phase 2 status — Passive discovery

## Deliverables (PRD §25, Phase 2)

| Deliverable | Status | Where |
|---|---|---|
| Subfinder adapter | Done (real, checksum-pinned) | `app/adapters/subfinder.py`, `backend/Dockerfile` |
| dnsx adapter + internal resolver config | Done | `app/adapters/dnsx.py`; `TRASHSCAN_DNS_RESOLVERS` |
| Asset normalization | Done | `app/services/normalization.py` |
| Target history + passive schedules | Done | `app/api/scans.py` (`/timeline`), `app/api/schedules.py`, `app/services/schedule_service.py` |
| Celery worker + scheduler | Done | `app/celery_app.py`, `app/worker/` |

**Exit condition — "an assigned Scanner can complete passive discovery without active
approval, while discovered assets remain unapproved":** demonstrated by
`tests/test_api_authorization.py` and `tests/test_executions.py`. 53 backend tests pass.

## What changed since Phase 1

- Passive discovery is now **asynchronous**: `POST /api/targets/{id}/scans` (or the
  compatibility route `/passive-scan`) creates a `ScanExecution` in `QUEUED` and a Celery
  task runs Subfinder (domains only) then dnsx, normalizes results, and moves the
  execution to `COMPLETED` (or `FAILED`/`CANCELLED`, `partial` flag on incomplete stages).
- New **scan lifecycle state machine** (`app/services/execution_service.py`) implementing
  the PRD §10 transition table with terminal-state idempotency (NFR-08).
- New entities: `scan_executions`, `observations`, `schedules`, `schedule_occurrences`
  (migration `0002_phase2`).
- **Adapter interface reworked** (`StageInput`/`StageOutput`), safe subprocess helper
  (`app/adapters/_exec.py`: fixed argv, process-group, byte-capped output, SIGTERM→SIGKILL
  timeout). Registry selects real vs fake by `TRASHSCAN_SCANNER_MODE`.
- **Scheduler**: `beat` dispatches `scheduler_tick` and `lifecycle_sweep` every 30 s.
  Passive occurrences run automatically; a missed window becomes `EXPIRED` and is never
  run late (PRD §8.2); overlapping runs are `SKIP`ped by default.
- New compose services: `worker`, `beat`. `api` has a healthcheck; `worker`/`beat` wait
  for it.
- `lifecycle_sweep` already enforces approval-window expiry and the two-hour runtime cap
  for executions that carry those timestamps — the active workflow in Phase 3 sets them.

## Tool pinning (PRD §12.6)

`backend/Dockerfile` downloads Subfinder `2.6.6` and dnsx `1.2.1` at **build** time and
verifies each against the publisher's `*_checksums.txt`. The app never downloads tools
during a scan. Versions are captured per execution in `scan_executions.tool_versions`.

## New / relevant requirements

| ID | Status | Note |
|---|---|---|
| SCAN-01 | Partial | `PASSIVE` profile fully wired; `SAFE_ACTIVE`/`STANDARD_ACTIVE` are Phase 3 |
| SCAN-05 | Partial | Scanner cancels own scan, admin cancels any; emergency-stop is Phase 3 |
| SCAN-06 | Partial | Cancellation stops between stages, keeps partial results, audits reason; full process-tree kill is exercised in Phase 3 with long-running tools |
| SCAN-08 | Partial | Global + per-target concurrency gate in `ScanService.capacity_available`; per-tool rate limits passed to adapters |
| SCAN-10 | Done (passive) | tool versions, normalized args, parser version recorded |
| FIND-01 | Done (passive) | assets + observations; services/findings are Phase 3–4 |
| SCHED-01/02/03 | Done (passive) | explicit timezone stored, execution timestamps UTC, overlap prevented |
| NOTIF-03 | Done | requester notified on started/completed/failed/cancelled/timed-out |
| NFR-04 | Partial | `lifecycle_sweep` re-queues stuck `QUEUED`; full worker-restart reconciliation of `RUNNING` lands in Phase 3 with heartbeats |
| NFR-06 | Done | parsers tolerate malformed/truncated output (`tests/test_parsers.py`) |
| NFR-08 | Done | terminal states are idempotent |

## Known limitations carried forward

- Enqueue-after-commit is not yet a true transactional outbox; `lifecycle_sweep` re-queues
  anything left in `QUEUED`, which covers the crash window. Outbox lands before Phase 3
  active work.
- `ScanExecution.seq`-style audit ordering still assumes a single API/worker appending; a
  dedicated serialized append is needed when scaling workers.
- Passive schedules only (INTERVAL ≥ 15 min, or DAILY at HH:MM in a stored timezone).
  Active schedules with per-occurrence approval are Phase 3.
