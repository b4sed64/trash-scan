# Architecture

How Trash Scan is built and how a scan flows through it. Configuration lives in
[`CONFIGURATION.md`](CONFIGURATION.md); deployment topology in [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## 1. Services

`docker-compose.yml` runs six containers:

| Service | Image / build | Role |
|---|---|---|
| `web` | `frontend/` → nginx 1.27 | Serves the built React SPA on port 8080 and reverse-proxies `/api/*` to `api` so cookies stay first-party. |
| `api` | `backend/` → uvicorn | FastAPI app. On start, `entrypoint.sh` runs `alembic upgrade head`, then (if `RUN_SEED=1`) the seed, then the server. |
| `worker` | `backend/` → Celery worker | Executes scans. `--concurrency=2`. |
| `beat` | `backend/` → Celery beat | Periodic tasks. |
| `db` | postgres:16.6 | All durable state. Volume `db_data`. |
| `redis` | redis:7.4 | Celery broker + result backend. In-memory only (`--save "" --appendonly no`). |

`worker` and `beat` share the `api` service's environment (the `&backend_env` YAML anchor)
and mount the same `artifacts` volume (`TRASHSCAN_RESULT_ROOT=/app/artifacts/scans`).

### Backend layout (`backend/app/`)

```
main.py            FastAPI app factory, exception handlers, router wiring, /api/health
config.py          Settings (env-driven, TRASHSCAN_ prefix)
security.py        Argon2id hashing, session + CSRF token generation
models/            SQLAlchemy 2.0 ORM
db.py              engine / SessionLocal
bootstrap.py       first-run helpers
celery_app.py      Celery config
constants.py       the exact ethical-use attestation text, etc.
scan_profiles.py   profile -> stage list + the UI-option -> tool-argument allowlist

api/               HTTP routers: auth, targets, scans, schedules, findings, reports,
                   approvals, emergency, admin, maintenance, audit, notifications
services/          domain logic (see §3-§6)
adapters/          one module per scanner tool + a fake variant + a registry
worker/            runner.py (stage orchestration) + tasks.py (Celery task wrappers)
reports/           PDF (Jinja2 + WeasyPrint) and CSV (.zip) generation
alembic/versions/  0001_initial … 0007_scan_groups
```

---

## 2. Request path & authentication

The browser only talks to nginx. nginx serves static assets and proxies the API.

- **Session**: `POST /api/auth/login` sets an `HttpOnly`, `SameSite=Lax` session cookie
  (server-side session record) plus a readable CSRF cookie. Idle timeout 30 min, absolute
  12 h (`config.py`). `Secure` flag follows `TRASHSCAN_SESSION_COOKIE_SECURE`.
- **CSRF**: every unsafe method requires the CSRF cookie value echoed in the
  `X-CSRF-Token` header (double-submit). Enforced by a dependency in `api/deps.py`.
- **Authorization** (`services/authorization_service.py`): deny-by-default. Roles are
  `ADMINISTRATOR` and `SCANNER`. A scanner may act only on targets explicitly assigned to
  them; admin-only routers depend on `require_admin`.
- **First run**: `GET /api/auth/setup-status` reports `needs_setup` while the `users` table
  is empty; `POST /api/auth/setup` creates the first administrator (once).
- Session records are revoked on account disable, password change, and admin reset.

---

## 3. Scope enforcement

The single most security-critical path. Two modules:

- `services/scope_service.py` — pure logic: canonicalization, allow/deny evaluation,
  containment, ambiguity.
- `services/scope_db.py` — loads the admin-configured private CIDRs and deny rules and runs
  the evaluation against a `Target`.

**Allowed scope** = the set of private CIDRs an administrator adds under
Administration → Private scope. **Deny rules** = addresses/ranges that are always off
limits. The same evaluation runs at two points:

1. **Target creation / ad-hoc target from a scan request.** Canonicalize the input to one
   of IPv4 / CIDR / DOMAIN. Reject anything ambiguous or unparseable. Apply deny rules
   first (fatal). Require containment in an allowed CIDR.
2. **Immediately before an active scan launches** (`worker/runner.py`, `SCOPE-07`):
   re-resolve the target's DNS and re-evaluate **every** resolved address. A name that has
   moved out of scope, or a split-horizon / rebinding answer, fails the re-check and the
   execution ends `FAILED` with a `SCAN_SCOPE_RECHECK_FAILED` audit event. Literal IPs from
   an IPv4/CIDR target are included in the candidate set. httpx does **not** follow
   redirects — the `Location` header is captured and scope-checked separately.

Passive scans do OSINT/DNS only and are not gated by an active-scope containment check, but
the target itself must still exist and be in the caller's assignment set.

---

## 4. Scan model and lifecycle

### One scan, many targets

A scan is one logical unit keyed by `scan_group_id`. It owns one `ScanExecution` row per
target (`group_seq` / `group_size`). Single-target scans are groups of one. Migration
`0007_scan_groups` back-filled existing rows. One `ScanApproval` covers the whole group.
`services/scan_groups.py` derives the group's state and finds its approval on read.

### Profiles (`scan_profiles.py`)

Users never choose raw tool flags. A profile is a fixed stage list plus a capability set;
each stage's argv is assembled from product-defined options only.

| Profile | Class | Stages | Notes |
|---|---|---|---|
| `PASSIVE` | passive | `subfinder` → `dnsx` | Public OSINT + DNS resolution. No approval. `subfinder` runs only for DOMAIN targets. |
| `SAFE_ACTIVE` | active | `dnsx` → `nmap` → `httpx` → `nuclei` | Nmap **TCP-connect**, service metadata, HTTP inspection, low-impact reviewed Nuclei templates. |
| `STANDARD_ACTIVE` | active | `dnsx` → `nmap` → `httpx` → `nuclei` | Broader port set, service/version detection. SYN scan + OS detection **only** when `TRASHSCAN_ALLOW_RAW_PACKET=true` and `worker` has `NET_RAW`. |

Ports come from a built-in preset, an admin-defined named port set, and/or a typed list
(validated, capped at 6000 ports). Nmap timing is a template (`T2`/`T3`) chosen from
product options, never a raw flag.

### State machine (`services/execution_service.py`)

```
DRAFT ──▶ AWAITING_APPROVAL ──▶ APPROVED ──▶ QUEUED ──▶ RUNNING ──▶ COMPLETED
  │             │                   │  ▲        │  ▲        │
  │ (passive:   │ deny              │  │ pause  │  │ pause   ├─▶ FAILED  (scope re-check, parser error)
  │  no         └─▶ DENIED          │  └────────┘  └─────────┼─▶ TIMED_OUT (runtime cap from RUNNING)
  │  approval)                      │                        └─▶ CANCELLED (Stop / emergency stop)
  └──────────────────────────────▶ QUEUED (Start)      CANCELLING ──▶ CANCELLED
```

Terminal states: `COMPLETED`, `FAILED`, `TIMED_OUT`, `DENIED`, `EXPIRED`, `CANCELLED`.
`transition()` validates every move against an explicit `ALLOWED` table, writes one
`SCAN_STATE_CHANGE` audit event, and (for requester-visible states) one notification.
Terminal transitions are idempotent, so a duplicated queue message cannot double-count.

- **Nothing runs on its own.** `POST /api/scans` creates every execution idle:
  passive → `DRAFT`, active → `AWAITING_APPROVAL`. `POST /api/scans/{id}/start` (requester
  or admin) moves idle executions to `QUEUED` and enqueues them.
- **Pause** (`/pause`) pulls `QUEUED` executions back out of the run queue —
  `→ APPROVED` (active, keeps the approval window) or `→ DRAFT` (passive) — before they
  begin. A `RUNNING` execution can only be **Stopped**.
- **Stop** (`/stop`) sets a cancel flag on every non-terminal execution; the worker's guard
  polls it ~1/s and lands the run in `CANCELLED` with partial results retained.
- Group state is derived: all `COMPLETED` → `COMPLETED`; all `CANCELLED` → `CANCELLED`; a
  mix including `COMPLETED` → `PARTIAL`; otherwise the earliest active state.

### Approval workflow (`api/approvals.py`)

An active scan submits the **exact** attestation string
([`constants.ACTIVE_SCAN_ATTESTATION`](../backend/app/constants.py)) — a mismatch is a 422.
That creates one `ScanApproval` for the group and notifies administrators. An admin
approves or denies:

- **Approve** sets the approval `APPROVED` with `expires_at = now + APPROVAL_WINDOW_MINUTES`
  (default 120) and moves every execution `AWAITING_APPROVAL → APPROVED`. It does **not**
  run the scan — the requester presses Start within the window or `lifecycle_sweep` expires
  it (`EXPIRED`). Re-approving is a 409.
- A **scheduled** occurrence is the exception: on approval it goes straight to `QUEUED` and
  runs, because the schedule is the standing intent.
- **Deny** moves executions to `DENIED` with the reason.

### Execution (`worker/runner.py`)

1. **Pre-flight** (one short transaction): bail if already terminal; cancel if an emergency
   stop applies or a cancel was requested; hold in `QUEUED` if no capacity
   (`lifecycle_sweep` re-enqueues later); for active scans run the DNS scope re-check
   (§3); transition `QUEUED → RUNNING`, set the runtime deadline.
2. **Run stages** with no DB session held. Each stage is a subprocess (`adapters/_exec.py`
   creates a process group, `SIGTERM` then `SIGKILL` after `CANCEL_GRACE_SECONDS`) with a
   per-stage timeout and the configured rate limits. Hostnames discovered by `dnsx` feed
   the later stages; web ports feed `httpx`/`nuclei`. A cancel/timeout guard is polled
   between and within stages.
3. **Persist**: `normalization.apply_stage_outputs` + `findings.record_findings` in one
   transaction (a parser exception → `FAILED`, never a worker crash). Then the terminal
   transition (`COMPLETED` / `TIMED_OUT` / `CANCELLED`), the `SCAN_RESULTS_NORMALIZED`
   audit event, and `comparison.build_and_store`.

### Scheduling & sweeps (`worker/tasks.py`, `services/schedule_service.py`)

`beat` fires three periodic tasks:

| Task | Interval | Does |
|---|---|---|
| `scheduler_tick` | 30 s | Advance due schedules. Passive occurrences enqueue. Active occurrences create a paused `AWAITING_APPROVAL` execution + approval. A missed window is recorded `EXPIRED`, never run late. Changing attestation-relevant schedule fields invalidates the stored attestation. |
| `lifecycle_sweep` | 30 s | Expire approved-but-unstarted executions past their window; reconcile emergency stop; enforce the `MAX_RUNTIME_MINUTES` cap on `RUNNING`; re-enqueue `QUEUED` executions when capacity frees. |
| `retention_sweep` | hourly | Delete raw output and executions older than the 7-day retention window. |

### Emergency stop (`services/emergency.py`)

One admin control (`POST /api/emergency-stop`) records an active stop, cancels queued
executions, and blocks new starts. `_exec.py` terminates the process groups of running
stages. It stays in force until an admin clears it; only one can be active at a time.

---

## 5. Normalization, fingerprints, comparison

- **Normalization** (`services/normalization.py`): stage outputs become `Asset`, `Service`
  and `Observation` rows. Discovered assets are stored **unapproved** — discovery is not
  authorization.
- **Fingerprint** (`services/findings.py`): `sha256` over `[target_id, normalized asset,
  source tool, rule id, protocol, port, evidence key]`. Volatile values (timestamps, random
  response bytes, free text) never enter it, so the same issue is recognised across runs.
  A tool that reports the same indicator once per probe still produces exactly one
  `FindingSighting` per run.
- **Comparison** (`services/comparison.py`): after a scan completes, its sightings are
  classified against the most recent **completed** execution of the same target with a
  *compatible* profile:
  - `NEW` — in this run, not the baseline.
  - `STILL_OBSERVED` — in both, unchanged.
  - `CHANGED` — in both, but severity or evidence changed.
  - `NOT_OBSERVED` — in the baseline, not this run. **This never means "resolved."** If the
    owning stage was incomplete or failed this run, the finding is reported as a
    *limitation* instead of `NOT_OBSERVED`.

---

## 6. Tamper-evident audit (`services/audit_service.py`)

`AuditService.append(actor, action, object_type, object_id, payload)` writes one immutable
`AuditEvent`. Each row stores `prev_hash` (the previous row's `curr_hash`) and its own
`curr_hash = sha256(seq, ts, actor, action, object_type, object_id, canonical(payload),
prev_hash)`. A transaction-scoped **Postgres advisory lock** serialises appends so the API,
worker and beat never race the sequence number (no-op on SQLite in tests).

The Logs page (`POST /api/audit/verify`) recomputes the entire chain and reports the first
`seq` where a hash does not match, or "Chain intact". It is tamper-*evident*: a database or
host administrator with direct storage access can still rewrite history — but not silently.

Audited actions include account lifecycle, auth success/failure/logout, scope and deny-rule
changes, target creation, attestation submission, approval grant/deny, every scan state
change, `SCAN_STARTED` / `SCAN_PAUSED` / `SCAN_STOP_REQUESTED`, scope re-checks, results
normalized, comparison stored, report generation, every export download, emergency stop,
retention actions, and tool/template maintenance.

---

## 7. Scanner tools & the fake mode

`adapters/` has one module per tool (`subfinder`, `dnsx`, `httpx`, `nmap`, `nuclei`), a
shared subprocess runner (`_exec.py`), a `fake.py` with deterministic stubs, and a
`registry.py` that returns the real or fake adapter based on `TRASHSCAN_SCANNER_MODE`.

`backend/Dockerfile` pins each ProjectDiscovery tool to an exact version
(`SUBFINDER 2.6.6`, `DNSX 1.2.1`, `HTTPX 1.6.9`, `NUCLEI 3.3.7`) and verifies the download
against the publisher's `*_checksums.txt` **at build time**. httpx is installed as
`httpx-pd` to avoid clashing with the Python `httpx` client. Nmap comes from the Debian
package. The Nuclei template set under `backend/templates/nuclei` is an immutable allowlist
with a content-hash manifest validated during the build (`verify_template_set`). Every tool
runs with update checks disabled — **nothing is fetched at runtime.**

`SCANNER_MODE=fake` produces stable, offline results and is what the test suite and
`scripts/demo_seed.sh` use.

---

## 8. Data & volumes

| Volume | Holds | Deleted by |
|---|---|---|
| `trashscan_db_data` | Postgres — accounts, targets, scope, executions, findings, sightings, comparisons, schedules, notifications, the audit chain. | `docker compose down -v` |
| `trashscan_artifacts` | Per-execution raw tool output (`TRASHSCAN_RESULT_ROOT`) and generated PDF/CSV reports. | `docker compose down -v`; individual entries by `retention_sweep`. |

Backup/restore of both volumes: [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md). After a restore,
run **Logs → Verify chain now**.
