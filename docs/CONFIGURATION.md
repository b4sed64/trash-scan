# Configuration reference

Every backend setting is an environment variable read by the `api`, `worker` and `beat`
containers. Names use the prefix `TRASHSCAN_` (defined in
[`backend/app/config.py`](../backend/app/config.py)). No secret is baked into an image.

There are three layers, innermost wins:

1. **Code defaults** — `Settings` in `config.py`. Safe, conservative values.
2. **`docker-compose.yml`** — the `api` service's `environment:` block (anchored as
   `&backend_env` and reused by `worker` and `beat`). This is where the container-level
   defaults for a compose deployment live.
3. **`.env`** — a handful of top-level keys (`POSTGRES_PASSWORD`, `SCANNER_MODE`,
   `RUN_SEED`, `DNS_RESOLVERS`, the `TRASHSCAN_SEED_*` / `DEMO_*` credentials) that
   `docker-compose.yml` interpolates. Copy `.env.example` to `.env` and edit.

To change anything not surfaced in `.env`, add it to the `backend_env` anchor in
`docker-compose.yml` and `docker compose up -d`.

---

## `.env` keys (compose interpolation)

| Key | Default | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | `trashscan` | Password for the `db` service and the API's connection string. **Change before any real use.** |
| `SCANNER_MODE` | `real` | `real` → run the pinned Subfinder/dnsx/Nmap/httpx/Nuclei binaries. `fake` → deterministic offline stub adapters (no network, used by the test suite and the demo). |
| `RUN_SEED` | `0` | `1` → the `api` entrypoint runs `python -m app.seed` on start (minimal dev data). Leave `0` for a clean first-run you drive through the UI. |
| `DNS_RESOLVERS` | *(empty)* | Comma-separated internal DNS resolvers for the lab. Empty → use the container's system resolver. |
| `TRASHSCAN_SEED_ADMIN` / `TRASHSCAN_SEED_ADMIN_PASSWORD` | `admin` / `change-me-admin-123` | Credentials the **minimal seed** (`RUN_SEED=1`) creates. Change them. |
| `TRASHSCAN_SEED_SCANNER` / `TRASHSCAN_SEED_SCANNER_PASSWORD` | `scanner` / `change-me-scanner-123` | Scanner account the minimal seed creates. |
| `TRASHSCAN_SEED_CIDR` | `10.10.0.0/16` | Allowed CIDR the minimal seed adds to scope. |
| `TRASHSCAN_SEED_TARGET` | `10.10.5.20` | Target the minimal seed defines and assigns. |
| `DEMO_ADMIN_PW` / `DEMO_SCANNER_PW` | `demo-admin-12345` / `demo-scanner-12345` | Credentials used by `scripts/demo_seed.sh` (the fuller demo scenario). |

Seed data is intended for a throwaway database — run either seed against a fresh volume.

---

## Database

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_DATABASE_URL` | `postgresql+psycopg://trashscan:trashscan@db:5432/trashscan` | SQLAlchemy URL. Compose builds it from `POSTGRES_PASSWORD`. The test suite points this at a throwaway SQLite file. |
| `TRASHSCAN_AUTO_CREATE` | `0` (compose) | `1` creates tables from the ORM metadata instead of running migrations — development only. Production path is `alembic upgrade head`, run by `backend/entrypoint.sh`. |

## Sessions, CSRF & passwords

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_SESSION_COOKIE_SECURE` | `true` (code) / `false` (compose) | Marks the session and CSRF cookies `Secure`. Keep `false` only for plain-HTTP localhost; set `true` the moment TLS terminates in front, or the cookies are dropped. |
| `TRASHSCAN_SESSION_COOKIE_NAME` | `trashscan_session` | `HttpOnly` session cookie name. |
| `TRASHSCAN_CSRF_COOKIE_NAME` | `trashscan_csrf` | Non-`HttpOnly` cookie; the SPA echoes it in the `X-CSRF-Token` header (double-submit). |
| `TRASHSCAN_CSRF_HEADER_NAME` | `X-CSRF-Token` | Header the API expects on every unsafe method. |
| `TRASHSCAN_SESSION_IDLE_MINUTES` | `30` | Sliding inactivity timeout. |
| `TRASHSCAN_SESSION_ABSOLUTE_HOURS` | `12` | Hard cap on a session's lifetime regardless of activity. |
| `TRASHSCAN_ARGON2_TIME_COST` | `3` | Argon2id iterations. |
| `TRASHSCAN_ARGON2_MEMORY_COST_KIB` | `65536` | Argon2id memory (64 MiB). |
| `TRASHSCAN_ARGON2_PARALLELISM` | `2` | Argon2id lanes. |

Passwords are enforced at ≥ 12 characters everywhere (setup, admin-created accounts,
self-service change, admin reset). Disabling an account, changing a password, or an admin
reset revokes that user's other sessions.

## CORS / frontend

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_FRONTEND_ORIGIN` | `http://localhost:5173` (code) / `http://localhost:8080` (compose) | Allowed browser origin. Behind a reverse proxy, set this to the real dashboard URL (e.g. `https://trashscan.lab.example.com`). |
| `TRASHSCAN_ENVIRONMENT` | `development` | Free-form label. |

## Queue / worker

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_REDIS_URL` | `redis://redis:6379/0` | Celery broker + result backend. |
| `TRASHSCAN_CELERY_TASK_ALWAYS_EAGER` | `false` | `true` runs tasks synchronously in-process (used by the test suite). |
| `TRASHSCAN_SCANNER_MODE` | `real` | Same meaning as `SCANNER_MODE`; compose passes it through. |
| `TRASHSCAN_RESULT_ROOT` | `/app/artifacts/scans` | Per-execution bounded result directories (on the `artifacts` volume). |
| `TRASHSCAN_DNS_RESOLVERS` | *(empty)* | Same as `DNS_RESOLVERS`. |
| `TRASHSCAN_ENABLE_DNS_RESOLUTION` | `true` | When `false`, scope previews skip live DNS (offline / test). |
| `TRASHSCAN_RUN_SEED` | `0` | Same as `RUN_SEED`; read by the `api` entrypoint. |

## Concurrency & rate limits

Conservative defaults (PRD §22). Raise only with lab-owner agreement.

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_MAX_GLOBAL_EXECUTIONS` | `2` | Executions running or queued across the whole system. |
| `TRASHSCAN_MAX_PER_TARGET_EXECUTIONS` | `1` | Concurrent executions against one target. |
| `TRASHSCAN_MAX_PARALLEL_STAGES` | `2` | Parallel stages within an execution. |
| `TRASHSCAN_DNS_QUERIES_PER_SECOND` | `20` | dnsx rate cap. |
| `TRASHSCAN_HTTP_REQUESTS_PER_SECOND` | `10` | httpx rate cap. |
| `TRASHSCAN_NUCLEI_REQUESTS_PER_SECOND` | `10` | Nuclei rate cap. |
| `TRASHSCAN_RETRY_MAX` | `1` | Stage retry attempts. |
| `TRASHSCAN_RETRY_BACKOFF_SECONDS` | `5` | Delay between retries. |
| `TRASHSCAN_MAX_RESPONSE_BYTES` | `2000000` | Per-response body cap held in memory. |
| `TRASHSCAN_MAX_EVIDENCE_BYTES` | `8000` | Evidence snippet stored per finding. |

## Time limits

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_APPROVAL_WINDOW_MINUTES` | `120` | An approved active scan must be **started** within this window or the approval expires. |
| `TRASHSCAN_MAX_RUNTIME_MINUTES` | `120` | Hard runtime cap measured from `RUNNING`; the scan is terminated as `TIMED_OUT` (partial results kept). |
| `TRASHSCAN_CANCEL_GRACE_SECONDS` | `10` | Grace between `SIGTERM` and `SIGKILL` when cancelling a process group. |

## Active-scan profile bounds

The scanner only ever invokes product-approved options — never a raw flag from user input.

| Variable | Default | Notes |
|---|---|---|
| `TRASHSCAN_ALLOW_RAW_PACKET` | `false` | Master switch for SYN scan + OS detection. Requires `cap_add: ["NET_RAW"]` on the `worker` service **and** a completed Phase 0 raw-packet spike. While `false`, Nmap runs TCP-connect only. |
| `TRASHSCAN_SAFE_ACTIVE_PORTS` | `22,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443` | Default port set for `SAFE_ACTIVE`. |
| `TRASHSCAN_STANDARD_ACTIVE_PORTS` | `1-1024,1433,1521,2049,2375,3000,3306,3389,5432,5900,5985,6379,8000,8080,8443,9200,11211,27017` | Default port set for `STANDARD_ACTIVE`. |
| `TRASHSCAN_NMAP_TIMING_SAFE` | `T2` | Nmap timing template for `SAFE_ACTIVE` (chosen from product options, not a raw flag). |
| `TRASHSCAN_NMAP_TIMING_STANDARD` | `T3` | Nmap timing template for `STANDARD_ACTIVE`. |
| `TRASHSCAN_HTTPX_FOLLOW_REDIRECTS` | `false` | httpx does not follow redirects; the `Location` header is captured and scope-checked instead. |
| `TRASHSCAN_HTTPX_MAX_REDIRECTS` | `0` | Redirect hops httpx may follow (kept at 0). |

Administrators can also define **named port sets** in the UI (Administration → Port Sets);
a scan picks a built-in preset, a defined set, and/or a typed list. Any spec is validated
and capped at 6000 ports.

---

## Enabling TLS (summary)

1. Put a TLS-terminating reverse proxy (e.g. Caddy) in front of port 8080.
2. In `.env` / compose: `TRASHSCAN_SESSION_COOKIE_SECURE=true` and
   `TRASHSCAN_FRONTEND_ORIGIN=https://<your-host>`.
3. `docker compose up -d`.

Full walkthrough: [`DEPLOYMENT.md`](DEPLOYMENT.md#reach-the-dashboard-from-another-machine-on-the-lan).
