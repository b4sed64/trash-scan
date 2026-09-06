# Trash Scan

A self-hosted reconnaissance dashboard for a single student security team operating an
authorized virtual lab. See [`Trash_Scan_PRD.md`](Trash_Scan_PRD.md) for the full product
definition.

> **This repository implements the full MVP (Phases 1–5).** Passive discovery
> (Subfinder + dnsx) and active scanning (Nmap TCP-connect + ProjectDiscovery httpx + a
> restricted, hash-pinned Nuclei template set) run asynchronously through a Celery worker
> against real, checksum/version-pinned tool binaries; set `SCANNER_MODE=fake` for offline
> development. Every active execution needs a typed attestation and a fresh administrator
> approval. Findings are normalized with stable fingerprints and classified against a
> compatible baseline (NEW / STILL_OBSERVED / CHANGED / NOT_OBSERVED). PDF and CSV reports,
> 7-day retention cleanup, and a tool/template maintenance workflow are in place. SYN scan
> and OS detection stay disabled until the raw-packet capability is proven
> (`TRASHSCAN_ALLOW_RAW_PACKET`) — see [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) for the
> criterion-by-criterion status and the per-phase notes in [`docs/`](docs/).

## Quick start (Docker Desktop on Windows)

```sh
cp .env.example .env        # optional; edit POSTGRES_PASSWORD etc.
docker compose up --build
```

Then open <http://localhost:8080> and complete first-run administrator setup.

| Service | URL | Notes |
|---|---|---|
| Web dashboard | http://localhost:8080 | nginx serving the built SPA, proxies `/api` |
| API (direct) | http://localhost:8000 | FastAPI; OpenAPI docs at `/docs` |
| PostgreSQL | internal | volume `db_data` |
| Redis | internal | Celery broker/result backend |
| worker | internal | Celery worker — runs scan executions |
| beat | internal | Celery beat — `scheduler_tick` + `lifecycle_sweep` every 30 s |

### Optional seed data

```sh
RUN_SEED=1 docker compose up --build
```

Creates a lab range `10.10.0.0/16`, an enabled `scanner` account, and one target assigned
to it. Credentials come from `.env` — change them before using this anywhere real.

## Running the tests

```sh
docker build -t trashscan-api ./backend
docker run --rm -e TRASHSCAN_ENABLE_DNS_RESOLUTION=false trashscan-api pytest
```

The suite (40 tests) covers IP/CIDR/domain canonicalization, allow/deny precedence,
DNS-rebinding / split-answer rejection, public-target boundaries, the audit hash chain
(including tamper detection), role + assignment enforcement through the HTTP API, CSRF,
session invalidation on account disable, and the fake adapter.

## Architecture (this phase)

| Component | Technology | Status |
|---|---|---|
| Web client | React + TypeScript + Vite, served by nginx | Implemented |
| API | Python FastAPI (sync SQLAlchemy 2.0) | Implemented |
| Database | PostgreSQL 16, Alembic migrations | Implemented |
| Queue / scheduler | Redis + Celery (`worker`, `beat`) | Implemented |
| Scan worker | Python + pinned CLI tools | Subfinder, dnsx, Nmap, httpx, restricted Nuclei (real) |
| Reports | Jinja2 + WeasyPrint; Python `csv` | PDF + CSV(.zip), formula-injection escaping, export audit |

### Security-critical modules (require human review on every change)

- [`backend/app/services/scope_service.py`](backend/app/services/scope_service.py) — target
  canonicalization and active-scope enforcement (deny-first, containment, ambiguity).
- [`backend/app/services/authorization_service.py`](backend/app/services/authorization_service.py)
  — deny-by-default role and assignment checks.
- [`backend/app/services/audit_service.py`](backend/app/services/audit_service.py) — the
  append-only SHA-256 hash chain and its verifier.
- [`backend/app/security.py`](backend/app/security.py) — Argon2id password hashing, session
  and CSRF tokens.

## Documentation

| Doc | Contents |
|---|---|
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Running locally, on another machine, LAN access + TLS, worker reachability |
| [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) | `pg_dump` / `psql` backup and restore of the `db_data` volume |
| [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) | Every PRD §24 acceptance criterion → where it's implemented and tested |
| [`docs/PRD_EVALUATION.md`](docs/PRD_EVALUATION.md) | Assessment of the PRD, ambiguities resolved, risks |
| `docs/PHASE{1..5}_STATUS.md` | Per-phase deliverable and requirement mapping |

## Data & backup

State lives in the `db_data` (database) and `artifacts` (raw output + reports) Docker
volumes. See [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md).

## Safety boundary

Trash Scan performs passive discovery and (in later phases) authorized active
reconnaissance only. It does not exploit vulnerabilities, test credentials, brute-force
names, cause denial of service, or provide evasion controls. Its technical controls
supplement — they do not replace — the team's responsibility to obtain permission.
