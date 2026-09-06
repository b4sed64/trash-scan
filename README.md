# Trash Scan

A self-hosted reconnaissance dashboard for a single student security team operating an
**authorized** virtual lab. One `docker compose` stack per machine — no SaaS, no central
server, no telemetry.

Trash Scan performs **passive discovery** and **authorized active reconnaissance** only. It
does not exploit vulnerabilities, test credentials, brute-force names, cause denial of
service, or provide evasion controls. Its technical controls supplement — they do not
replace — the team's responsibility to obtain permission. See
[Safety boundary](#safety-boundary).

The full product definition is [`Trash_Scan_PRD.md`](Trash_Scan_PRD.md). This repository
implements the complete MVP (PRD Phases 1–5) plus the post-MVP refinements recorded in
[`docs/POST_MVP.md`](docs/POST_MVP.md).

---

## Contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation (step by step)](#installation-step-by-step)
- [First-run configuration (in the UI)](#first-run-configuration-in-the-ui)
- [Configuration reference](#configuration-reference)
- [Seed & demo data](#seed--demo-data)
- [Running the tests](#running-the-tests)
- [Everyday operations](#everyday-operations)
- [Documentation index](#documentation-index)
- [Safety boundary](#safety-boundary)

---

## What it does

Trash Scan gives a small team a shared, auditable place to **inventory** an authorized lab
network and **track how it changes** over time.

| Area | What you get |
|---|---|
| **Scope control** | An administrator declares the lab's private ranges (the *allowed* scope) and optional *deny* rules. Every target and every discovered address is checked against that scope, deny-first. Out-of-scope or ambiguous inputs are refused. |
| **Targets** | Administrators define IPv4 / CIDR / domain targets and assign each to the scanners who may work it. A "public" target additionally requires a typed authorization attestation. Defining a target never starts anything. |
| **Scans** | One scan can cover any mix of chosen targets and typed hosts/IPs/CIDRs. Every scan is **created idle** and a person presses **Start**; **Pause** returns a just-started scan to the queue, **Stop** cancels it. Three profiles: `PASSIVE` (discovery only), `SAFE_ACTIVE`, `STANDARD_ACTIVE`. |
| **Approval workflow** | Active scans require the exact ethical-use attestation text *and* a fresh administrator approval. One approval covers the whole scan (all its targets), authorizes exactly one run, and expires if it is not started within two hours. |
| **Findings** | Tool output is normalized into assets, services and findings. Each finding gets a **stable fingerprint** so the same issue is recognised across runs and classified against a compatible baseline: `NEW`, `STILL_OBSERVED`, `CHANGED`, `NOT_OBSERVED`. "Not observed" never means "fixed". |
| **Per-host review** | A scan detail page shows dashboard-style severity tiles and a collapsible per-host breakdown (state, stages, findings, services, assets). |
| **Reports & exports** | Per-target PDF (rendered server-side) and CSV `.zip` exports. CSV cells that could be read as spreadsheet formulas are neutralised. Every export is recorded in the audit log. |
| **Tamper-evident audit** | Every security-relevant event is written to an append-only, SHA-256 **hash-chained** log. Anyone can re-verify the whole chain from the Logs page. |
| **Scheduling** | Recurring passive scans, or recurring active scans where each occurrence still needs its own approval. A missed occurrence is recorded as expired, never silently run later. |
| **Emergency stop** | One control terminates every running scan process group and blocks new starts until an administrator clears it. |
| **Retention** | Raw tool output and old executions are swept on a 7-day schedule. |

### Pages

| Page | Purpose |
|---|---|
| **Dashboard** | KPI tiles, findings-by-severity, a severity-ranked threats table, your targets, reports/exports. |
| **Targets** | Define targets (admin), assign scanners, preview scope, generate reports, schedule scans. |
| **Scans** | Build a scan; Scan History with compact Start / Pause / Stop controls and a Review link to the scan detail page. |
| **Approvals** (admin) | Approve or deny pending active scans; see recent decisions. |
| **Logs** | The audit chain — filter by action, search by scan/object id, order ascending/descending, verify the chain. |
| **Administration** (admin) | Accounts + password reset, private scope (allowed CIDRs), deny rules, reusable port sets, scanner tool/template maintenance. |
| **Your Account** | Change your own password. |

Two roles: **ADMINISTRATOR** (full control) and **SCANNER** (works only assigned targets).
The first administrator is created through first-run setup; there is no default account.

---

## How it works

### Stack

| Component | Technology | Runs as |
|---|---|---|
| Web client | React 18 + TypeScript + Vite, built to static files | `web` (nginx; also reverse-proxies `/api`) |
| API | Python 3 + FastAPI, synchronous SQLAlchemy 2.0, Pydantic v2 | `api` (uvicorn) |
| Database | PostgreSQL 16, schema managed by Alembic migrations | `db` |
| Queue / scheduler | Redis + Celery | `redis`, `worker`, `beat` |
| Scanners | Pinned, checksum-verified CLI binaries (or deterministic fakes) | invoked by `worker` |

`docker-compose.yml` wires all six services together. The `api` container's entrypoint
runs `alembic upgrade head` before starting, so **schema migrations apply automatically**
on every `up`.

### Request path

The browser only ever talks to nginx on port 8080. nginx serves the built SPA and proxies
`/api/*` to the `api` container, so session cookies stay first-party. The API authenticates
every request with a server-side session cookie (`HttpOnly`, 30-minute idle / 12-hour
absolute lifetime) and enforces a double-submit CSRF token on every unsafe method.
Authorization is deny-by-default: a scanner sees only targets explicitly assigned to them.

### Scope enforcement (`scope_service.py`, `scope_db.py`)

An administrator configures the *allowed* scope as a set of private CIDRs, plus optional
*deny* rules. Target creation and every active scan launch run the same check:

1. Canonicalize the input (IPv4, CIDR, or domain). Ambiguous or unresolvable input is
   rejected.
2. Apply deny rules first. A deny match is fatal.
3. Require containment within an allowed CIDR.
4. For active scans, **re-resolve DNS immediately before launch** and re-check every
   resolved address — a name that has moved out of scope (or a split-horizon answer) stops
   the scan. Redirects are captured and scope-checked rather than followed.

### Scan lifecycle (`execution_service.py`, `worker/runner.py`)

A scan is one logical unit identified by a `scan_group_id`; it holds one `ScanExecution`
per target. Each execution moves through an audited state machine:

```
                                 ┌── Start ──┐
passive:  DRAFT ─────────────────┤           ▼
active:   DRAFT ─▶ AWAITING_APPROVAL ─▶ APPROVED ─▶ QUEUED ─▶ RUNNING ─▶ COMPLETED
                        │                   ▲          │         │
                        ▼                   └─ Pause ──┘         ├─▶ FAILED
                     DENIED                                      ├─▶ TIMED_OUT   (2 h runtime cap)
                                                                 └─▶ CANCELLED   (Stop / emergency stop)
```

- **Nothing runs on its own.** A passive scan waits in `DRAFT`; an active scan needs one
  administrator approval and then waits in `APPROVED`. A person presses **Start** to enqueue
  it; **Pause** returns a `QUEUED` execution to `APPROVED`/`DRAFT`; **Stop** cancels it.
  (Scheduled occurrences are the one exception — the schedule is the standing intent, so an
  approved occurrence runs immediately.)
- The group's state is derived from its executions (all `COMPLETED` → `COMPLETED`; a mix of
  completed and cancelled/failed → `PARTIAL`).
- The Celery `worker` picks up a `QUEUED` execution, re-checks scope and the emergency-stop
  flag, then runs the profile's stages (`subfinder` → `dnsx` → `nmap` → `httpx` → `nuclei`,
  as applicable) as sandboxed subprocesses with per-stage timeouts and rate limits. A stray
  or duplicated queue message is a no-op — terminal states are idempotent.
- `beat` runs `scheduler_tick` and `lifecycle_sweep` every 30 s (advance schedules, expire
  unused approvals, enforce the runtime cap, re-enqueue when capacity frees) and
  `retention_sweep` hourly.

### Findings & change tracking (`normalization.py`, `findings.py`, `comparison.py`)

Raw tool output is parsed into `Asset`, `Service` and `Finding` rows. Each finding is
fingerprinted from stable identity fields (logical target, normalized asset, source tool,
rule id, protocol/port, evidence key) — never from volatile data like timestamps. One
`FindingSighting` is recorded per finding per run. After a scan completes, a `ScanComparison`
classifies every finding against the most recent **compatible** prior scan of the same
target as `NEW` / `STILL_OBSERVED` / `CHANGED` / `NOT_OBSERVED`.

### Tamper-evident audit (`audit_service.py`)

`AuditService.append` writes one row per security-relevant event, each carrying the SHA-256
hash of the previous row plus its own content — an append-only chain. A Postgres advisory
lock serialises appends so the API, worker and beat can write concurrently without racing
the sequence number. The Logs page recomputes the whole chain on demand and reports the
first break, if any. It is tamper-*evident*, not tamper-proof: someone with direct database
access can still rewrite history, but not without the verifier noticing.

### Scanner tools

Subfinder, dnsx, ProjectDiscovery httpx (installed as `httpx-pd`), Nmap and Nuclei are
pinned to exact versions and verified against the publisher's checksums **at image build
time**. The application never downloads a tool or a template at runtime
(`-disable-update-check` / `-duc`). The Nuclei template set is an immutable allowlist with a
content-hash manifest that is validated during the build. `SCANNER_MODE=fake` swaps in
deterministic stub adapters for offline development and testing.

SYN scan and OS detection require raw-packet capability and stay **disabled** until
`TRASHSCAN_ALLOW_RAW_PACKET=true` *and* the `worker` service is granted `NET_RAW`.

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Prerequisites

- **Docker** with the Compose plugin:
  - Windows / macOS: Docker Desktop.
  - Linux / Kali: Docker Engine + `docker-compose-plugin`.
- ~4 GB free RAM for the stack, plus disk for the `db_data` and `artifacts` volumes.
- TCP ports **8080** (dashboard) and **8000** (API, for direct access / OpenAPI docs) free
  on the host. Change the left-hand side of the `ports:` mappings in `docker-compose.yml`
  if they clash.
- For real scanning: the `worker` container must have network routes to the lab segments
  you intend to scan (see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md#worker-reachability-to-the-lab)).
  For evaluation without a lab, use `SCANNER_MODE=fake`.
- Outbound internet access **only for the first build** (to pull base images and the pinned
  scanner binaries). Nothing is downloaded at runtime.

## Installation (step by step)

1. **Clone the repository.**

   ```sh
   git clone https://github.com/b4sed64/trash-scan.git
   cd trash-scan
   ```

2. **Create your environment file.**

   ```sh
   cp .env.example .env
   ```

   Open `.env` and, at minimum:
   - set `POSTGRES_PASSWORD` to something other than the default;
   - set `SCANNER_MODE=fake` if you are evaluating without a lab network, or leave it
     `real` to use the pinned tools.

   Every setting is explained in [Configuration reference](#configuration-reference).

3. **Build and start the stack.**

   ```sh
   docker compose up --build          # add -d to run detached
   ```

   The first build pulls base images and the checksum-verified scanner binaries and takes a
   few minutes. Subsequent starts are fast.

4. **Wait for the services to become healthy.**

   ```sh
   docker compose ps                  # db, redis, api should show "healthy"
   curl -s http://localhost:8000/api/health
   ```

   The `api` container applies database migrations automatically before it reports healthy.

5. **Open the dashboard** at <http://localhost:8080>.

6. **Complete first-run setup** — create the first administrator (username ≥ 3 characters,
   password ≥ 12 characters). This is a one-time action; there is no default login.

7. **Configure scope and users** (next section).

To stop: `docker compose down`. To stop **and delete all data**: `docker compose down -v`.

## First-run configuration (in the UI)

Log in as the administrator you just created, then:

1. **Administration → Private scope** — add the lab's allowed CIDR(s), e.g. `10.10.0.0/16`.
   Nothing can be scanned until an allowed range exists.
2. **Administration → Deny rules** *(optional)* — add any addresses/ranges that must never
   be touched even though they fall inside an allowed CIDR.
3. **Administration → Accounts** — create `SCANNER` accounts for team members and activate
   them.
4. **Targets** — define the hosts / CIDRs / domains you are authorized to assess. Mark a
   target "public" only with the typed attestation.
5. **Targets → assign** — assign each target to the scanners who may work it.
6. **Scans** — build a scan, press **Start** (for active profiles: submit the attestation,
   have an administrator approve it, then Start).

## Configuration reference

All backend settings are environment variables read by the `api`, `worker` and `beat`
containers (prefix `TRASHSCAN_`). `docker-compose.yml` sets sensible container defaults;
`.env` overrides the few you are expected to touch. The complete list with defaults is in
**[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)**.

The ones most deployments change:

| `.env` key | Default | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | `trashscan` | Database password (used by `db` and the API connection string). **Change before anything real.** |
| `SCANNER_MODE` | `real` | `real` runs the pinned CLI tools; `fake` uses deterministic offline stubs. |
| `RUN_SEED` | `0` | `1` loads minimal development seed data on start (see below). |
| `DNS_RESOLVERS` | *(empty)* | Comma-separated internal resolvers for the lab; empty uses the system resolver. |

Set directly in `docker-compose.yml` (under the `api` service / `backend_env` anchor) when
you need them:

| Variable | Default | Purpose |
|---|---|---|
| `TRASHSCAN_SESSION_COOKIE_SECURE` | `false` | Set `true` once TLS terminates in front (Secure cookies are dropped over plain HTTP). |
| `TRASHSCAN_FRONTEND_ORIGIN` | `http://localhost:8080` | Allowed origin for CORS / cookie checks; set to your real dashboard URL behind a proxy. |
| `TRASHSCAN_ALLOW_RAW_PACKET` | `false` | Enables SYN scan + OS detection; also requires `cap_add: [NET_RAW]` on `worker`. |

Time limits, concurrency, rate limits and the active-profile port sets have conservative
defaults documented in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md); tune them there.

## Seed & demo data

| Goal | Command |
|---|---|
| **Minimal seed** — one lab CIDR, one scanner, one assigned target (credentials from `.env`, `TRASHSCAN_SEED_*`). | `RUN_SEED=1 docker compose up -d --build` |
| **Full demo** — admin + scanner, two assigned targets, a completed passive scan, two started active scans (so the baseline comparison shows `NEW` + `STILL_OBSERVED`), one pending approval, generated reports. Run against an already-running stack. | `SCANNER_MODE=fake docker compose up -d --build` then `./scripts/demo_seed.sh` |

The demo script prints its logins (`admin` / `demo-admin-12345`,
`scanner1` / `demo-scanner-12345`). Both seeds are meant for a throwaway database — run them
against a fresh volume.

## Running the tests

```sh
docker build -t trashscan-api ./backend
docker run --rm -e TRASHSCAN_SCANNER_MODE=fake trashscan-api pytest
```

The suite (**120 tests**) covers IP/CIDR/domain canonicalization, allow/deny precedence,
DNS-rebinding / split-answer rejection, public-target boundaries, the audit hash chain
(tamper detection, filter/query), role + assignment enforcement through the HTTP API, CSRF,
session invalidation on account disable / password change / admin reset, the scan-execution
state machine and idempotency, one-scan-many-targets grouping, manual start / pause / stop,
scheduling, the active-scan approval workflow (expired approval, replay, scope re-check,
runtime timeout, emergency stop), tool-output parsers, finding fingerprints and baseline
comparison, CSV formula neutralization + PDF generation, retention, the maintenance
workflow, port-spec validation, and the fake adapters.

## Everyday operations

| Task | Command |
|---|---|
| Start / rebuild | `docker compose up -d --build` |
| Stop | `docker compose down` |
| Stop and wipe all data | `docker compose down -v` |
| Follow logs | `docker compose logs -f api worker beat` |
| Update to latest code | `git pull && docker compose up -d --build` (migrations auto-apply) |
| Back up / restore | see [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) |

Persistent state lives in two Docker volumes: `trashscan_db_data` (Postgres — accounts,
findings, the audit chain) and `trashscan_artifacts` (raw scan output + generated reports).
Both survive `down`/`up` and code updates; only `down -v` deletes them. After any restore,
run **Logs → Verify chain now** — it must report "Chain intact".

## Documentation index

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the system is built and how a scan flows through it — services, request path, scope enforcement, the lifecycle state machine, normalization + comparison, the audit chain, the scanner adapters. |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Every environment variable, its default, and when to change it. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Running locally, on another machine, LAN access + TLS, worker reachability to the lab. |
| [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) | `pg_dump` / `psql` backup and restore of the volumes. |
| [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) | Every PRD §24 acceptance criterion → where it is implemented and tested. |
| [`docs/POST_MVP.md`](docs/POST_MVP.md) | Everything added after the five PRD phases — new endpoints, audit actions, migrations, UI structure. |
| [`docs/PRD_EVALUATION.md`](docs/PRD_EVALUATION.md) | Assessment of the PRD, ambiguities resolved, risks. |
| `docs/PHASE{1..5}_STATUS.md` | Point-in-time per-phase deliverable and requirement mapping. |

### Security-critical modules (require human review on every change)

- [`backend/app/services/scope_service.py`](backend/app/services/scope_service.py) — target
  canonicalization and active-scope enforcement (deny-first, containment, ambiguity).
- [`backend/app/services/authorization_service.py`](backend/app/services/authorization_service.py)
  — deny-by-default role and assignment checks.
- [`backend/app/services/audit_service.py`](backend/app/services/audit_service.py) — the
  append-only SHA-256 hash chain and its verifier.
- [`backend/app/security.py`](backend/app/security.py) — Argon2id password hashing, session
  and CSRF tokens.

## Safety boundary

Trash Scan performs passive discovery and authorized active reconnaissance only. It does
**not** exploit vulnerabilities, test or spray credentials, brute-force names, cause denial
of service, or provide detection-evasion controls. Scope, authorization and the audit trail
are product behaviour, not add-ons. The operator remains responsible for holding written
permission for every target and lab segment.
