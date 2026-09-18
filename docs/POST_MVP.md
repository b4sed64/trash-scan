# Post-MVP changes

The five PRD phases (see `PHASE1_STATUS.md` … `PHASE5_STATUS.md`) delivered the MVP. This
document records the changes made **after** that, mostly UX refinements and a few small
capabilities. Nothing here relaxes a scope, authorization, or audit control.

## Schema

| Migration | Adds |
|---|---|
| `0006_port_sets` | `port_sets` table — administrator-defined reusable named port selections |
| `0007_scan_groups` | `scan_executions.scan_group_id` / `group_seq` / `group_size` and `scan_approvals.scan_group_id`, so one scan spans many targets. Existing rows are back-filled (each becomes a group of one). |

`alembic upgrade head` (run automatically by `backend/entrypoint.sh`) is at `0007_scan_groups`.

## One scan, many targets, manual start

A scan is now **one logical unit** identified by a `scan_group_id`, with one
`ScanExecution` per target sharing that id. Single-target scans are groups of one.

- **Nothing runs on its own.** Every scan is created idle and the requester (or an
  administrator) presses **Start**. A passive scan waits in `DRAFT` (shown as *READY*
  in the UI); an active scan needs one administrator approval covering every target
  first and then waits in `APPROVED`.
- **Start** moves the idle executions to `QUEUED` and enqueues them. For an active scan
  this must happen inside the approval window (`APPROVAL_WINDOW_MINUTES`, default 120) or
  the approval expires.
- **Pause** pulls a just-started scan back out of the run queue before it begins —
  `QUEUED` → `APPROVED` (active) or `QUEUED` → `DRAFT` (passive). A scan that is already
  `RUNNING` can only be Stopped.
- **Stop** cancels the whole group — every non-terminal execution, before or during the run.
- Scheduled active occurrences are the exception: the schedule is the standing intent, so
  an approved occurrence starts automatically. Scheduled passive occurrences also run on
  their schedule.
- Group state is derived from the child executions (e.g. all `COMPLETED` → `COMPLETED`;
  a mix of `COMPLETED` and `CANCELLED`/`FAILED` → `PARTIAL`).

## New / changed API

| Method & path | Purpose |
|---|---|
| `POST /api/auth/change-password` | Change your own password (min 12); revokes your other sessions. |
| `POST /api/admin/accounts/{id}/reset-password` | Administrator sets a new password for an account; revokes that account's sessions. |
| `GET /api/findings` | Findings across every target the caller may see, ranked by severity (drives the dashboard). |
| `GET /api/audit/actions` | Distinct audit action types, for the Logs filter UI. |
| `GET /api/audit/events` | Now accepts `action` (repeatable), `q` (free-text over object id / seq / payload values), and `order=asc\|desc`. |
| `POST /api/scans` | Create **one scan** over any mix of `target_id(s)` and typed `target_value(s)` (host / IP / CIDR); duplicates collapsed. Returns `{"scan_id", "state", "executions": [...]}` — one execution per resolved target, all sharing `scan_id`. The scan is created **idle** (passive → `DRAFT`, active → `AWAITING_APPROVAL`); nothing runs until Start. An administrator may create an as-yet-undefined target on the fly (deny rules still apply); a scanner cannot. Active scans accept a `port_preset` and/or `ports` spec and need one approval for the group. |
| `GET /api/scans` | Now returns **scan groups** (one row per `scan_id`) with aggregate `state`, `target_count`, per-target `targets[]`, and the group `approval`. |
| `GET /api/scans/{scan_id}` | Accepts a group id (or a bare execution id). Returns the group summary plus `hosts[]` (per-target state, stages, assets, services, findings) and a `summary` block (severity counts, totals, hosts completed) for the per-host review view. |
| `POST /api/scans/{scan_id}/start` | Requester or administrator. Moves idle executions (`APPROVED`, or passive `DRAFT`) to `QUEUED` and enqueues them; 409 if there is nothing to start or the approval window elapsed. |
| `POST /api/scans/{scan_id}/pause` | Requester or administrator. Pulls every `QUEUED` execution back out of the run queue — to `APPROVED` (active) or `DRAFT` (passive); 409 if nothing is queued or the scan is already running. |
| `POST /api/scans/{scan_id}/stop` | Requester or administrator. Requests cancellation of every non-terminal execution in the group; 409 if the scan is already finished. |
| `GET /api/scans/port-presets` | Built-in port presets plus the administrator-defined port sets. |
| `GET/POST/DELETE /api/admin/port-sets` | CRUD for administrator-defined port sets. The spec is validated and canonicalised (`scan_profiles.parse_port_spec`, capped at 6000 ports). |

`POST /api/targets/{id}/scans` is unchanged and still returns a single execution (plus its `scan_id`).
`POST /api/scans/{execution_id}/cancel` still cancels a single execution.

## New audit actions

`PASSWORD_CHANGED`, `PASSWORD_RESET`, `PORT_SET_ADDED`, `PORT_SET_REMOVED`, `SCAN_STARTED`,
`SCAN_PAUSED`, `SCAN_STOP_REQUESTED`. Failed logins
(`AUTH_FAILURE`) and logout (`AUTH_LOGOUT`) now record the actor as `user:<username>` (was
`username:<x>` and a raw user id respectively); a failed login also records
`attempted_username` in the payload.

## UI structure

- **Dashboard** (`/`) is now the security overview: KPI stat tiles (open findings,
  needs-attention = critical + high, targets, running scans, pending approvals), a
  findings-by-severity bar, a severity-ranked threats & vulnerabilities table, the
  targets-in-scope list, and reports & exports. The separate "Findings & reports" page was
  merged here; `/reports` redirects to `/`.
- **Notification bell** in the sidebar on every page — unread badge plus a dropdown with
  per-item and mark-all-read.
- **Logs** — the "Audit trail" page renamed. Filter by one or more action types, free-text
  search (a scan's execution id pulls its whole chain, including approval events), and
  ascending / descending order. Rows expand to show the payload and hash links.
- **Scans → New Scan** — pick any number of defined targets from a checkmark dropdown
  and/or type hosts/IPs/CIDRs; choose a profile; for active profiles pick a rate, a port
  selection (built-in presets and defined port sets via a checkmark dropdown, and/or a
  typed list), and type the attestation. The chosen targets become **one scan**, created
  idle — you press Start to run it.
- **Scans → Scan History** lists scan groups with compact **Start** / **Pause** / **Stop**
  controls (icon buttons) and a **Review** link to the **scan detail** page (`/scans/:id`),
  which has dashboard-style severity tiles, a findings-by-severity bar, and a per-host
  breakdown (state, stages, findings, services, assets, observations). Each host block is
  a collapsible card. A not-yet-started passive scan shows as *READY*.
- **Scan detail → per-host diagnostics.** The Stages table now shows, per stage, its
  status, duration, and — for anything that failed or ran incomplete — the tool's own
  note or the first line of its stderr (full text on hover). A host with any failed stage
  is flagged right on its collapsed card summary ("N stages failed"), so a silent tool
  failure (a bad CLI flag, a permissions error, a missing binary) is visible without
  digging through the database. A collapsible Observations table surfaces everything a
  stage recorded that isn't a finding, service, or asset — dnsx's raw DNS records,
  httpx's TLS/tech-detection data, katana's crawled endpoints, OSINT's WHOIS/CT-log
  results — scoped to that one execution (`GET /api/scans/{id}` now includes
  `observations` per host, backed by `Observation.execution_id`, alongside the
  `stages` array's existing `stderr_excerpt` and `note`, which the UI simply wasn't
  rendering before).
- **Approvals** — one row per scan; multi-target scans show every target and are approved
  once. Approving no longer runs the scan (except scheduled occurrences); the requester
  presses Start.
- **Your Account** (`/account`, reached from the sidebar) — change your own password.
- **Administration → Port Sets** — define reusable named port selections.
- Page headings and placeholder / button labels are title case; the main content column is
  centred in the space beside the sidebar; the login page and the sidebar show the raccoon
  mark (the raccoon emoji, matching the favicon and the background watermark); password
  fields have a show/hide toggle; every page carries a faint raccoon / raccoon-in-a-bin
  watermark (turned 45° CCW).

## Bug fixes

### Active scans against a public-boundary target always failed

`worker/runner.py`'s pre-launch scope re-check re-derived "in scope" addresses with
its own private-CIDR-only filter (`_within_scope`), duplicating part of
`scope_service.evaluate_active_scope` incompletely. Any target approved solely via a
**public boundary** (an `is_public` target with attestation, no matching private
CIDR — the normal way to authorize scanning your own public domain) always resolved
to zero in-scope addresses and failed at `SCAN_SCOPE_RECHECK_FAILED`, even though the
authoritative scope decision said `allowed: true`. Private-CIDR lab targets never hit
this, which is why it shipped unnoticed. Fixed by deriving `in_scope_ips` from
`decision.allowed` itself (which already vets every candidate address against both
private CIDRs and public boundaries) instead of re-filtering by private CIDR alone;
the redundant, incomplete `_within_scope` helper is removed. Regression test:
`test_active_workflow.py::test_active_scan_launches_against_a_public_boundary_target`.

### httpx and Nuclei silently failed on every real active scan

Two independent, pre-existing bugs, both invisible in `SCANNER_MODE=fake` (the test
suite never exercises a real tool subprocess) and both masked by the scan still
reaching `COMPLETED` — a scan's overall state doesn't reflect whether every stage
inside it actually succeeded.

1. **A poisoned `$HOME`.** Every scanner subprocess runs through
   `adapters/_exec.py::run_tool` with a deliberately minimal environment (no leaked
   app secrets) that hardcoded `HOME=/tmp`. The Dockerfile's build-time Nuclei
   template validation (`RUN HOME=/tmp nuclei -validate ...`) runs as root before
   `USER appuser` is set, so it created `/tmp/.config/nuclei` as a root-owned,
   mode-700 directory baked into the image. At runtime the non-root `appuser`
   launched every real tool with that same `HOME=/tmp`, so Nuclei and katana (which
   both need to read/write a config directory under `$HOME`, katana even just to
   parse its flags) hit permission denied. nmap and dnsx don't touch `$HOME`, which
   is why they kept working and the failure went unnoticed. Fixed: `run_tool` now
   uses `HOME=/app` (already `chown`'d to `appuser`, never touched by a root build
   step); the build step also removes `/tmp/.config` afterward so the image never
   ships the poisoned directory at all.
2. **A flag that doesn't exist.** `adapters/httpx.py` passed `-max-response-size` —
   that's a **katana** flag, not an httpx one. httpx-pd exited immediately
   (`flag provided but not defined`, exit code 2) before making a single request,
   regardless of the `$HOME` fix. Replaced with httpx-pd's real flag,
   `-response-size-to-read`. The other four adapters' flags were audited against
   their real `-h` output while fixing this; no other mismatches found.

Both were verified by invoking the real pinned binaries inside the rebuilt image
with the exact sanitized environment `run_tool` constructs, not just by unit test —
`SCANNER_MODE=fake` can't catch either class of bug by construction.

### The UI didn't show a stage's own failure detail

`GET /api/scans/{id}` already returned each stage's `stderr_excerpt` and `note` (the
two bugs above were originally diagnosed by querying the database directly), but the
scan detail page only ever rendered `"{stage}{ok ? '' : ' ✗'}"` — a stage failing was
visible, *why* it failed was not, and a tool's non-finding output (raw DNS records,
TLS/tech-detection data, crawled endpoints, WHOIS/CT-log results) had nowhere to
show at all on that page. See "Scan detail → per-host diagnostics" above.

## Enrichment scanning (Phase 6 — complete)

Findings from data the tool bundle already had access to, one new external lookup
shipped off by default, and one new pinned tool for broader crawling. See
`Trash_Scan_PRD.md` §25 "Phase 6" for the full writeup.

- **TLS/certificate posture** (source tool `httpx`) — `tls-cert-expired` (HIGH),
  `tls-cert-expiring-soon` (MEDIUM, within 30 days), `tls-self-signed` (LOW),
  `tls-hostname-mismatch` (MEDIUM), `tls-deprecated-protocol` (HIGH for SSLv3,
  MEDIUM for TLS 1.0/1.1). Derived from the `-tls-grab` data httpx was already
  capturing. No new tool, no PRD amendment.
- **Passive DNS-record posture** (source tool `dnsx`, domain targets only) —
  `dns-spf-missing` / `dns-spf-permissive` (`+all`), `dns-dmarc-missing` /
  `dns-dmarc-policy-none` (`p=none`), `dns-caa-missing`. dnsx now also resolves
  `_dmarc.<domain>` so the DMARC record is actually queried. Runs for both passive
  and active scans of a domain target, same as the rest of dnsx's output. No new
  tool, no PRD amendment.
- **External OSINT lookups** (source tool `osint`, domain targets only, **off by
  default** — `TRASHSCAN_ENABLE_EXTERNAL_OSINT` / `.env`'s `ENABLE_EXTERNAL_OSINT`)
  — unlike the two above, this one *is* a new kind of capability: the app itself
  makes a live outbound call to crt.sh and to RDAP at scan time, sending the
  target's domain to each. crt.sh subdomains become new discovered (unapproved)
  hostname assets, same as Subfinder's. RDAP registrar/creation/expiry/nameservers
  become observations; an expiring or already-lapsed registration becomes a
  finding (`osint-domain-registration-expiring-soon` MEDIUM /
  `osint-domain-registration-expired` HIGH — a lapsed domain can be re-registered
  by a third party). Runs only in the `PASSIVE` profile, positioned right after
  Subfinder so any newly-discovered subdomains still get resolved by the dnsx
  stage that follows. Both external calls go through an injectable fetcher
  (`adapters/osint.py::set_fetcher`, the same pattern `scope_db.set_resolver`
  uses for DNS) so the test suite never touches the network; the fake adapter
  always runs deterministically regardless of the flag, the same as every other
  fake adapter ignoring the real one's gating flags.
- `services/comparison.py`'s `_STAGE_FOR_TOOL` map gained `httpx`, `dnsx`, and
  `osint` entries so these findings participate correctly in
  NEW/STILL_OBSERVED/CHANGED/NOT_OBSERVED baseline comparison instead of only
  ever showing as a "did not complete" limitation.
- **Broader crawling (ProjectDiscovery katana)** — the one addition that's a
  genuinely new tool, not an extension of one already in the bundle (PRD §12.6).
  Pinned to `v1.7.0` and checksum-verified at build time, same as the other four
  (katana's release uses a differently-named checksums file than the others, so
  it gets its own verified-download step in `backend/Dockerfile` rather than
  joining their shared loop). New stage `katana`, wired into `SAFE_ACTIVE` and
  `STANDARD_ACTIVE` between `httpx` and `nuclei`: it crawls the web hosts httpx
  already probed (bounded depth — 1 for Safe, 2 for Standard; bounded pages per
  host; a bounded time budget; no headless/browser execution; no automatic form
  filling; default host-based scope stays on) and feeds newly discovered
  endpoints into that same execution's Nuclei stage via the existing
  `web_probes` mechanism (`worker/runner.py`'s feed-forward condition now also
  accepts katana's `endpoint`-tagged observations, not just nmap's `web-port`
  ones). Not in the `PASSIVE` profile. Emits no findings itself — it only
  broadens what Nuclei gets to see.
- Fixed a latent bug this surfaced: the fake `httpx`/`nuclei` adapters derived a
  finding's host with `probe.split(":")[0]`, which assumed every probe was a bare
  `ip[:port]`. Once the fake katana adapter started adding full URLs to the same
  probe pool, that produced a bogus host (`"http"`) and duplicate `Finding` rows
  for the same underlying host. Fixed with a shared `_probe_host()` helper that
  handles both shapes, matching how a real httpx/nuclei invocation would.

## Tests

The suite is now **151 tests**. Post-MVP additions:
`test_passwords.py`, `test_audit_query.py`, `test_scan_targeting.py`, `test_port_sets.py`,
`test_scan_groups.py` (one scan across many targets; one approval; manual start / pause /
stop; passive scans wait for Start too; `GET /api/scans/{id}` surfaces per-host
observations and each stage's `stderr_excerpt`/`note`), `test_enrichment.py` (TLS-posture
and SPF/DMARC/CAA finding rules, end to end through both scan classifications),
`test_osint.py` (crt.sh/RDAP parsing, the off-by-default gate, and the injected-fetcher
adapter path — fully offline), `test_katana.py` (endpoint parsing against katana's
real JSONL shape, profile wiring, and end-to-end through the fake pipeline).

## Concurrency fix

`AuditService.append` now takes a transaction-scoped Postgres advisory lock before
computing the next sequence number, so the API, Celery worker and beat can append
concurrently without colliding on `audit_events.seq` (commit `218e678`). No-op on SQLite
(single-threaded tests).
