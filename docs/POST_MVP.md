# Post-MVP changes

The five PRD phases (see `PHASE1_STATUS.md` … `PHASE5_STATUS.md`) delivered the MVP. This
document records the changes made **after** that, mostly UX refinements and a few small
capabilities. Nothing here relaxes a scope, authorization, or audit control.

## Schema

| Migration | Adds |
|---|---|
| `0006_port_sets` | `port_sets` table — administrator-defined reusable named port selections |
| `0007_scan_groups` | `scan_executions.scan_group_id` / `group_seq` / `group_size` and `scan_approvals.scan_group_id`, so one scan spans many targets. Existing rows are back-filled (each becomes a group of one). |
| `0008_port_set_protocol` | `port_sets.protocol` (`TCP`/`UDP`, default `TCP`, backfilled via `server_default`) — see "Port profiles" below. |
| `0009_coverage_ledger` | `coverage_entries` table — per-execution, per-check-family coverage records (PRD v2 Phase 8). See "Coverage ledger" below. |
| `0010_canonical_issues` | `issues` + `occurrences` tables — canonical issue identities projected from findings (PRD v2 Phase 9). Tables only; backfill is a separate idempotent service. See "Canonical issues" below. |
| `0011_candidate_associations` | `candidate_associations` table — offline candidate CVE associations, kept separate from findings/issues (PRD v2 Phase 11). See "Offline CVE intelligence" below. |
| `0012_issue_review` | Issue review/remediation columns (validation + remediation state, owner, due date, closure metadata) and a `risk_exceptions` table (PRD v2 Phase 12). See "Issue review & remediation" below. |
| `0013_exploitability_assessment` | `exploitability_assessments` table — offline, analytical issue→module assessments (PRD v2 Phase 13). No execution. See "Exploitability assessment" below. |
| `0014_lab_environment` | `lab_environments` / `lab_fixtures` / `recovery_records` — lab isolation/snapshot/recovery gating metadata (PRD v2 Phase 15). Fake controller; no execution. See "Lab isolation & recovery" below. |
| `0015_proof_execution` | `proof_plans` / `proof_attempts` / `proof_evidence` — one-shot proof lifecycle (PRD v2 Phase 16). Fake-backed and hard-gated; BLOCKED unless the lab-proof flag is on and a fixture is ready. See "One-shot proof execution" below. |
| `0016_stream_events` | `stream_events` — durable, ordered status/output/evidence events for the live execution workspace (PRD v2 Phase 17). Fake streams; sanitized output. See "Live execution workspace" below. |

`alembic upgrade head` (run automatically by `backend/entrypoint.sh`) is at `0016_stream_events`.

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
| `POST /api/scans` | Create **one scan** over any mix of `target_id(s)` and typed `target_value(s)` (host / IP / CIDR); duplicates collapsed. Returns `{"scan_id", "state", "executions": [...]}` — one execution per resolved target, all sharing `scan_id`. The scan is created **idle** (passive → `DRAFT`, active → `AWAITING_APPROVAL`); nothing runs until Start. An administrator may create an as-yet-undefined target on the fly (deny rules still apply); a scanner cannot. Active scans accept a `port_preset` and/or `ports` spec (TCP) and need one approval for the group. `udp_ports` is also accepted, validated the same way (`scan_profiles.parse_port_spec`) — only meaningful for `STANDARD_ACTIVE` with UDP scanning enabled; `null`/omitted falls back to `TRASHSCAN_STANDARD_UDP_PORTS`. |
| `GET /api/scans` | Now returns **scan groups** (one row per `scan_id`) with aggregate `state`, `target_count`, per-target `targets[]`, and the group `approval`. |
| `GET /api/scans/{scan_id}` | Accepts a group id (or a bare execution id). Returns the group summary plus `hosts[]` (per-target state, stages, assets, services, findings) and a `summary` block (severity counts, totals, hosts completed) for the per-host review view. |
| `POST /api/scans/{scan_id}/start` | Requester or administrator. Moves idle executions (`APPROVED`, or passive `DRAFT`) to `QUEUED` and enqueues them; 409 if there is nothing to start or the approval window elapsed. |
| `POST /api/scans/{scan_id}/pause` | Requester or administrator. Pulls every `QUEUED` execution back out of the run queue — to `APPROVED` (active) or `DRAFT` (passive); 409 if nothing is queued or the scan is already running. |
| `POST /api/scans/{scan_id}/stop` | Requester or administrator. Requests cancellation of every non-terminal execution in the group; 409 if the scan is already finished. |
| `GET /api/scans/port-presets` | Built-in TCP port presets plus every administrator-defined port set (now including `protocol` and `note`), open to any authenticated user — the read path the Ports and Scans pages both use. |
| `GET/POST/DELETE /api/admin/port-sets` | Administrator-only CRUD for port sets. `protocol` (`TCP`/`UDP`, default `TCP`) plus the spec are validated (`scan_profiles.parse_port_spec`, capped at 6000 ports) and canonicalised. |
| `GET /api/issues` | Canonical issues across visible targets (PRD v2 Phase 9), each rolling up one or more findings, ranked by severity. |
| `GET /api/issues/{id}` | One canonical issue: per-surface occurrence history and the legacy finding ids it aliases. |
| `POST /api/admin/issues/backfill` | Administrator-only, audited (`ISSUES_BACKFILLED`). Rebuilds the canonical projection from existing findings; idempotent and lossless. |
| `GET /api/vulnintel/status` | Local CVE snapshot provider, effective date, schema version and stale flag (PRD v2 Phase 11). Offline; no target data sent. |
| `GET /api/targets/{id}/candidates` | Candidate CVE associations for a target, ranked by priority lane. Separate from the actionable finding/issue counts. |
| `POST /api/admin/vulnintel/refresh` | Administrator-only, audited (`ENRICHMENT_UPDATED`). Re-derives candidates for all completed scans from the current snapshot without a rescan. |
| `POST /api/issues/{id}/validate` | Set analyst validation (`VALIDATED`/`FALSE_POSITIVE`/`INCONCLUSIVE`); target access; audited `ISSUE_VALIDATION_SET`. |
| `POST /api/issues/{id}/assign` | Set owner / due date / desired state / plan (moves `OPEN`→`IN_PROGRESS`); audited `ISSUE_ASSIGNED`. |
| `POST /api/issues/{id}/mitigate` | Mark `MITIGATED` (controls reduce impact, condition not asserted removed); audited `ISSUE_MITIGATED`. |
| `POST /api/issues/{id}/accept-risk` | Administrator-only. Records a `risk_exceptions` row (reason + expiry required) and sets `RISK_ACCEPTED`; audited `RISK_ACCEPTED`. |
| `POST /api/issues/{id}/close` | Administrator-only. Marks `RESOLVED_VERIFIED` only with a qualifying negative or manual evidence; audited `ISSUE_CLOSED`. 409 if neither is present. |
| `GET /api/targets/{id}/report.json` | Redacted JSON export preserving candidates, excluded dispositions (with totals) and latest coverage; audited `REPORT_EXPORTED`. |
| `GET /api/proof/modules` | Reviewed proof-module registry (admitted + research-only). Offline; exposes no framework console. Gated by `enable_exploitability_assessment`. |
| `GET /api/issues/{id}/exploitability` | Offline exploitability assessment(s) for an issue — per-prerequisite state + derived eligibility. Never authorizes execution. |
| `POST /api/proof/modules/{id}/dry-run` | Validate a module's params/policy/cost with no target traffic. |
| `GET /api/lab/environments`, `POST /api/admin/lab/environments` | List / register lab environments (PRD v2 Phase 15). |
| `POST /api/admin/lab/environments/{id}/verify-isolation` | Record an isolation verification (simulated with the fake controller; audited `LAB_ISOLATION_VERIFIED`). |
| `GET /api/lab/fixtures`, `POST /api/admin/lab/fixtures` | List / register a fixture bound to a target. |
| `POST /api/admin/lab/fixtures/{id}/rehearse-restore` | Record a restore rehearsal (simulated; audited `LAB_RESTORE_REHEARSED`). |
| `GET /api/lab/fixtures/{id}/readiness` | Whether the fixture is proof-ready, and if not, exactly why. |
| `POST /api/proof/plans` | Create an immutable one-shot proof plan (operator; target access). Refuses un-admitted modules. |
| `POST /api/proof/plans/{id}/approve` | Administrator-only; requires the exact proof attestation; audited `PROOF_PLAN_APPROVED`. |
| `POST /api/proof/plans/{id}/execute` | One-shot execution; resolves `BLOCKED` unless the lab-proof flag is on and the fixture is ready; audited `PROOF_ATTEMPT_*`. |
| `GET /api/proof/attempts/{id}` | Attempt state + proof/recovery outcomes + nonce-correlated evidence. |
| `GET /api/proof/attempts/{id}/events?after=<seq>` | Durable status/output/evidence events for the live workspace, replayed after the reconnect cursor (PRD v2 Phase 17). |

`POST /api/targets/{id}/scans` is unchanged and still returns a single execution (plus its `scan_id`).
`POST /api/scans/{execution_id}/cancel` still cancels a single execution.

## New audit actions

`PASSWORD_CHANGED`, `PASSWORD_RESET`, `PORT_SET_ADDED`, `PORT_SET_REMOVED`, `SCAN_STARTED`,
`SCAN_PAUSED`, `SCAN_STOP_REQUESTED`, `ISSUES_BACKFILLED`, `ENRICHMENT_UPDATED`,
`ISSUE_VALIDATION_SET`, `ISSUE_ASSIGNED`, `ISSUE_MITIGATED`, `RISK_ACCEPTED`, `ISSUE_CLOSED`,
`ISSUE_REOPENED`, `LAB_ENVIRONMENT_REGISTERED`, `LAB_ISOLATION_VERIFIED`,
`LAB_FIXTURE_REGISTERED`, `LAB_RESTORE_REHEARSED`, `PROOF_PLAN_CREATED`,
`PROOF_PLAN_APPROVED`, `PROOF_ATTEMPT_BLOCKED`, `PROOF_ATTEMPT_COMPLETED`. Failed logins
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
  rendering before). Stages, Findings, Services, Assets, and Observations are each
  their own collapsible block within a host card — Stages and Findings open by
  default, the rest closed, so a host with a lot of history doesn't dump every
  table on screen at once.
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
- **Nmap NSE allowlist (PRD §12.1)** — the first Nmap capability beyond port/service/OS
  scanning. Adds a fixed, four-script allowlist to the Safe and Standard active profiles:
  `smb2-security-mode`, `smb-security-mode`, `ldap-rootdse`, `rdp-enum-encryption`, all
  Nmap-categorized `safe`/`discovery`/`default` — no `intrusive`, `brute`, or `vuln`
  category script is ever eligible. Passed to `--script` by exact comma-separated name
  only, never a category or wildcard, so a script's own internal `dependencies` entry
  (e.g. `smb-security-mode` depends on `smb-brute`, `ldap-rootdse` depends on
  `ldap-brute`) can never cause Nmap to schedule the brute-force script too — Nmap's
  scheduler only *orders* scripts that were both already selected, it never selects one
  on its own. `smb2-security-mode`/`smb-security-mode` output is turned into a
  severity-ranked `smb-signing-not-required` finding (MEDIUM when signing is disabled,
  LOW when enabled but not enforced) via a new pure function, `nmap.smb_signing_finding`,
  shared with the fake adapter the same way `httpx.tls_findings` is. `ldap-rootdse` and
  `rdp-enum-encryption` surface as `NSE`-kind observations only — their output isn't
  stable enough across environments to key a severity rule off with confidence, so no
  finding rule was written for them rather than guessing one. `ssl-enum-ciphers` was
  considered and dropped: Nmap itself categorizes it `intrusive`, which PRD §12.1
  explicitly excludes; httpx's existing `-tls-grab` posture findings already cover
  deprecated-protocol detection, so this isn't a coverage gap. `safe_active_ports`
  gained `389`/`636` so the Safe profile actually has LDAP open to run `ldap-rootdse`
  against (Standard's `1-1024` range already covered it). `services/comparison.py`'s
  `_STAGE_FOR_TOOL` map gained an `nmap` entry so these findings participate in
  NEW/STILL_OBSERVED/CHANGED/NOT_OBSERVED baseline comparison like every other tool's.
- **A second recon/vuln-scanning round**, added right after the NSE allowlist above:
  - **Two more NSE scripts**: `ssl-cert` (reads a certificate's validity period on
    non-HTTP TLS services — LDAPS, SMTP-STARTTLS, RDP-over-TLS — that httpx's
    `-tls-grab` never sees, since it only ever probes HTTP(S); reuses the
    `tls-cert-expired`/`tls-cert-expiring-soon` rule ids so it slots into the same
    posture story as httpx's TLS findings, just from a different source_tool) and
    `smb-protocols` (lists which SMB dialects a server accepts; flags SMBv1 as
    `smb1-enabled` HIGH by keying off Nmap's own literal `[dangerous, but default]`
    marker in the script's output — the protocol version implicated in
    EternalBlue/WannaCry). Both pure functions (`nmap.ssl_cert_findings`,
    `nmap.smb_protocols_finding`) added to the same `NSE_SCRIPTS` allowlist and
    `_findings_for_script` dispatcher the first four scripts use.
  - **Favicon fingerprinting (httpx)** — added `-favicon` to the httpx argv, which
    computes an mmh3 hash of `/favicon.ico`, the same technique Shodan's
    `http.favicon.hash` uses to identify a known product/CMS even when its version
    banner is hidden. Surfaces as a `TECH`/`favicon-hash` observation. This is
    genuinely one extra request per host (correcting an earlier description of it
    as "free" — it isn't zero-request, just a very lightweight, browser-normal one).
  - **PTR sweep of a CIDR target (dnsx)** — for a `CIDR` target, `worker/runner.py`
    now expands the approved range (same 1024-address bound as Nmap's literal-IP
    expansion) and feeds every address to dnsx, which already supported `-ptr`
    for a list of IPs; the only gap was that a CIDR target never got its
    addresses put in front of dnsx. Pure DNS traffic against the resolver, never a
    packet to the swept hosts, so it runs in the `PASSIVE` profile too, not just
    the active ones.
  - **4 new Nuclei templates** (13 total, up from 9), adapted from the
    MIT-licensed `projectdiscovery/nuclei-templates`, condensed to house style
    (single GET, `trashscan-` id, `author: trash-scan`): `exposed-panel-phpmyadmin`,
    `exposed-panel-grafana` (admin panels reachable without any special access),
    `eol-apache-httpd`, `eol-php` (version banner discloses software past its
    vendor end-of-life date, via Nuclei's `compare_versions()` DSL function against
    the same thresholds the upstream templates use). All `info` severity — detection,
    not a vulnerability by itself.
  - **SNMP discovery and NetBIOS `nbstat` were requested but not built in this
    round.** Both require Nmap to do a UDP scan (SNMP listens on UDP/161; NetBIOS
    name queries use UDP/137 — confirmed directly from Nmap's own
    `snmp-sysdescr.nse` portrule and `nbstat.nse`'s own usage example,
    `nmap -sU --script nbstat.nse -p137`). This adapter only ever ran `-sT`/`-sS`
    (TCP); UDP scanning was a PRD §12.1 deferred capability, not just an
    unimplemented flag, and adding it was a materially bigger feature than "add
    another script name" — scoped out as its own PRD item rather than folded
    into that batch. **Delivered in the very next round, below.**
- **UDP scanning (Standard active only) — un-defers the item above (PRD §12.1, §29).**
  Reuses the exact same raw-packet gate as SYN scan/OS detection
  (`TRASHSCAN_ALLOW_RAW_PACKET` + `NET_RAW`), so it inherits the same off-by-default,
  Phase-0-spike-pending posture without needing a new flag. Scoped to a fixed,
  curated port list (`TRASHSCAN_STANDARD_UDP_PORTS`, default: DNS/DHCP/TFTP/NTP/
  NetBIOS/SNMP/CLDAP/IPsec/syslog/RIP/IPP/SSDP/mDNS) rather than a broad sweep —
  the point was enabling two specific NSE scripts, not general UDP service
  discovery (a design choice confirmed with the user rather than assumed: broader
  curated list over a narrow 2-port one, Standard-only over both active profiles).
  Nmap's combined port-spec syntax (`-p T:<tcp-ports>,U:<udp-ports>` plus `-sU`
  alongside the existing `-sT`/`-sS`) does the actual work; verified directly
  against the real binary that this syntax parses and that the privilege check
  fires exactly like SYN scan's already does, before touching any code.
  - `snmp-sysdescr` and `nbstat` added to the NSE allowlist, but only ever
    included in `--script` when the UDP scan itself is enabled
    (`nmap._UDP_ONLY_SCRIPTS`) — never requested, and so never run, without it.
  - **Superseded by PRD v2 §8.2 / F1 (see "Phase 10" below): `snmp-sysdescr` is
    now DISABLED and removed from the allowlist** — relying on the default
    `public` community string is a credential probe under the preserved
    boundary. The paragraph below records the original rationale; it no longer
    describes shipped behavior.
  - `snmp-sysdescr` queries a device over SNMP using the well-known default
    `public` read-only community string. This was checked against Nmap's own
    `nselib/snmp.lua` before adding: `o.community = community or "public"` — the
    library only ever tries that one default, never a list, so this is a single
    default-credential check (the same category as the already-approved anonymous
    LDAP root DSE query), not a credential-guessing campaign. Its success alone
    (any non-empty response) becomes a `snmp-public-community-exposed` MEDIUM
    finding via the new `nmap.snmp_public_finding` pure function.
  - `nbstat` (NetBIOS name/user/MAC disclosure) surfaces as an observation only,
    matching the `ldap-rootdse`/`rdp-enum-encryption` precedent — it's
    asset-identification data, not a posture verdict.

## Port profiles (TCP/UDP) and a dedicated Ports page

Port sets existed since `0006_port_sets` but only as a section buried inside the
Administration page, TCP-only, with no relationship to the UDP-scan work above. Requested
directly: promote them to a first-class page, the same way Targets is one, and let a set
declare which protocol it's for.

- **`PortSet.protocol`** (`0008_port_set_protocol`, default `TCP`, backfilled via
  `server_default` so existing rows need no data migration) — a set is TCP or UDP, never
  mixed, matching how Nmap's own combined port spec (`-p T:...,U:...`) keeps the two apart.
  `PortSetCreate` validates it (`^(TCP|UDP)$`); port-number validation itself
  (`parse_port_spec`, 1–65535, 6000-port cap) doesn't change — it never depended on protocol.
- **`Ports` page** (`frontend/src/pages/Ports.tsx`, route `/ports`, nav link next to
  Targets) — replaces the "Port Sets" section removed from Administration. Visible to every
  authenticated user (reads `GET /api/scans/port-presets`, the same open endpoint the Scans
  page already used, now also carrying `protocol` and `note`); an Administrator-only form
  creates/removes profiles via `/api/admin/port-sets`, split into separate "TCP Profiles" and
  "UDP Profiles" tables.
- **UDP profiles actually do something.** A new `CreateScan.udp_ports` field (validated the
  same way as `ports`) flows through `_active_options` → `ScanExecution.options["udp_ports"]`
  → `worker/runner.py` → `nmap.py`, where it replaces `settings.standard_udp_ports` for that
  one scan when set (`str(inp.options.get("udp_ports") or settings.standard_udp_ports)`).
  Unset (the default) keeps today's fixed-list behavior exactly. On the Scans page, a UDP
  ports `MultiSelect` (sourced from `protocol: "UDP"` port sets only) plus a typed-ports field
  appear only for `STANDARD_ACTIVE`, composed client-side the same way the existing TCP ports
  picker already works (`compose()` is now a shared helper both call).
- The TCP ports picker on the Scans page now filters `port_sets` to `protocol !== "UDP"`, so
  a UDP profile can never accidentally end up in the TCP `-p` argument.

## Live execution workspace (PRD v2 Phase 17 — fake streams)

The streaming contract for the execution workspace, built on fake streams with
no target traffic (`services/stream.py`, `stream_events` via migration `0016`).

- **Durable, ordered events** per attempt with a monotonic `seq`, server UTC
  timestamp, and type (`STATUS` / `OUTPUT` / `EVIDENCE` / `GAP`). **Status in the
  attempt row is the authoritative lifecycle truth** — output events never
  overwrite it.
- **Output is sanitized at write time:** ANSI and control sequences stripped,
  HTML-escaped, per-payload bounded. Synthetic/fixture output is still treated as
  untrusted. The terminal renderer is display only, not an execution boundary.
- **Reconnect replays strictly after the client's last `seq` cursor**; a cursor
  older than the earliest retained event surfaces a `GAP` rather than silent
  loss. A `GET /api/proof/attempts/{id}/events?after=<seq>` endpoint provides the
  replay (access re-checked each call). Proof execution now emits durable
  status/output/evidence events, so a (BLOCKED) attempt already has a workspace
  history.
- **Bounded transcript** (~1 MiB/attempt): overflow emits a single `GAP`
  truncation marker and stops appending output (backpressure), rather than
  growing unbounded.

The progressive browser UI and the live WebSocket tail are the remaining
increment; the durable event store + replay contract + sanitization are in
place and tested (unauthorized observer, reconnect cursor, gaps, malicious
output, transcript overflow).

## One-shot proof execution (PRD v2 Phase 16 — fake-backed, hard-gated)

The proof lifecycle: immutable plan → proof-specific attestation → fresh
administrator approval → a single bounded execution → nonce-correlated evidence
→ separate recovery. Fake-backed (drives the Phase 14 fake adapter) and defended
by hard gates checked at execution:

- the `enable_lab_proof` flag (**off by default**),
- fixture **readiness** (verified isolation + restore rehearsal + HEALTHY + unlocked),
- a single global active proof, **one attempt per plan** (one-shot, no retry/schedule),
- the two-hour one-start approval window.

With the flag off and no ready fixture — the state of any non-lab environment —
**every execution resolves to `BLOCKED` before anything runs.** The full path is
implemented and tested (tests open the gates against the fake adapter), but it
cannot execute for real here; the genuine demonstration against a seeded
vulnerable fixture (and failure on its patched/negative fixture, plus replayed-
evidence rejection and verified restore) is the **real-lab acceptance gate**,
which this environment cannot satisfy.

- `ProofPlan` is immutable + hashed; changing module/target/options/budgets
  needs a new plan + approval. `create_plan` refuses an un-admitted module.
  `approve_plan` requires the exact proof attestation and is administrator-only.
- `ProofAttempt` carries independent lifecycle state and **separate proof and
  recovery outcomes** — a demonstrated proof with a failed recovery is both a
  proof and an unresolved recovery incident. Outcomes: `DEMONSTRATED` /
  `ATTEMPTED_NOT_DEMONSTRATED` / `INCONCLUSIVE` / `BLOCKED` / `ERROR`.
- **`DEMONSTRATED` requires the per-attempt marker to be echoed back AND a
  negative control to hold** — the framework merely reporting `Vulnerable` is
  never sufficient (defends against replayed/stale evidence and bare success).
- New API (operator/admin, audited): `POST /api/proof/plans`,
  `POST /api/proof/plans/{id}/approve` (admin + attestation),
  `POST /api/proof/plans/{id}/execute` (one-shot), `GET /api/proof/attempts/{id}`.

## Lab isolation & recovery (PRD v2 Phase 15 — fake controller)

The safety infrastructure that *gates* proof execution. It runs nothing against
a target; it models the isolation / snapshot / health / recovery preconditions
that must hold before any active capability could run.

- **`LabEnvironment` / `LabFixture` / `RecoveryRecord`** (migration `0014`).
  Isolation must be *proven* (`isolation_verified`) — private addressing alone
  is never enough. A fixture needs a bound snapshot, a recorded **successful
  restore rehearsal**, and a HEALTHY baseline; a snapshot's mere presence is
  insufficient (§21.6).
- **`services/lab.py`** with a `LabController` protocol and a **`FakeLabController`**
  (touches no hypervisor/network). `readiness(fixture, env)` returns `ready`
  only when isolation is verified, a snapshot is bound, a restore rehearsal
  succeeded, baseline health is HEALTHY, and the fixture is unlocked — otherwise
  it lists exactly what's missing. In this dev environment those preconditions
  can't truthfully pass, so **a fixture is never ready and real execution stays
  BLOCKED**, which is the intended outcome. Health vocabulary
  (HEALTHY/DEGRADED/UNKNOWN/RECOVERY_REQUIRED/RECOVERY_FAILED) and recovery
  outcomes (NOT_NEEDED/PENDING/VERIFIED_CLEAN/RESTORED_VERIFIED/RECOVERY_FAILED)
  per §21.6-21.7. A failed restore records `RECOVERY_FAILED` and keeps the
  fixture not-ready; an exclusive fixture lock prevents concurrent use.
- **New API (read for all, mutations admin-only, audited):**
  `GET /api/lab/environments` + `POST /api/admin/lab/environments`,
  `POST /api/admin/lab/environments/{id}/verify-isolation`,
  `GET /api/lab/fixtures` + `POST /api/admin/lab/fixtures`,
  `POST /api/admin/lab/fixtures/{id}/rehearse-restore`,
  `GET /api/lab/fixtures/{id}/readiness`. The verify/rehearse results are
  **simulated** with the fake controller and are clearly flagged as such — a
  real deployment must demonstrate target-only traffic / blocked
  control-plane+internet+other-targets and a real restore on the actual Windows/
  Docker topology before they mean anything (the real-lab gate).

Deferred: the real provider integration (follows the operator's hypervisor), a
separate disposable proof worker with enforced egress in compose, and the actual
on-topology isolation/restore proof (all `LAB_PENDING`).

## Restricted framework adapter (PRD v2 Phase 14 — fake/metadata backend)

The backend bridge to the exploitation framework (Metasploit), built as the
PRD prescribes: **fake-backed, no real framework contacted, nothing executed
against a target.** `services/framework.py` defines the *entire* permitted
surface — `capabilities`, `module_metadata`, `start_check`, `job_status`,
`job_result`, `cancel` — and nothing else. There is deliberately **no** generic
RPC, console passthrough, arbitrary datastore options, payload generation,
module loading, resource scripts, or local-shell fallback; their absence is the
contract, verified by a test asserting those methods do not exist.

- **`FakeFrameworkAdapter`** with sanitized native-response fixtures backs all
  development/tests. `get_framework_adapter()` always returns the fake in this
  phase; a real adapter (private authenticated RPC, reachable only inside the
  restricted worker boundary) is introduced later and stays withheld until the
  Phase 15 lab isolation/recovery gates — no state-changing operation runs
  before then.
- **Job correlation + idempotency:** `start_check` is idempotent on a client
  idempotency key (a lost ack / duplicated submit maps to one job), and
  `job_result` delivery is idempotent. Unsupported modules/jobs raise rather
  than fall back.
- **Conservative result interpretation (§21.4):** `interpret_native_result`
  maps `Appears`→candidate, `Detected`→product/service, `Vulnerable`→reviewed
  *condition* evidence (never demonstrated impact — a check verdict is not an
  executed exploit), and `Safe`→a conclusive negative **only** when telemetry
  proves the service was reached and the check completed; otherwise, and for
  `Unknown`/`Unsupported`/`Error`/`Timeout`/absent, it is INCONCLUSIVE and never
  establishes absence.

No schema, API or config change — this is the adapter layer only. It is wired
into actual proof execution in a later phase (16), behind the lab gates.

## Exploitability assessment (PRD v2 Phase 13 — offline, analytical only)

The first slice of the §21 exploitability work. It is **entirely offline: no
target contact and no execution** — not even a framework "check". It maps a
canonical issue to a reviewed module manifest and evaluates each prerequisite
against evidence already collected.

- **Reviewed module registry** (`backend/app/data/proof_modules.json`,
  `services/exploitability.py`). Each module is a reviewed contract (§21.3):
  admission state (`ADMITTED` / `RESEARCH_ONLY` / disabled), issue mapping,
  claim, compatibility, `check_classification`, typed inputs, expected effect,
  prerequisites, lab-fixture/cleanup/recovery. RESEARCH_ONLY modules are visible
  references and are never executable. Shipping the manifest is **not** admission
  of executable modules for a real engagement — a human admits actual revisions.
- **Per-prerequisite states** (§21.4): `SATISFIED` / `MISSING` / `CONTRADICTED` /
  `UNKNOWN` / `STALE`, each with provenance. Overall eligibility is derived
  separately: `NEEDS_EVIDENCE` / `INCOMPATIBLE` / `BLOCKED_POLICY` /
  `ELIGIBLE_FOR_PROOF`. Crucially, the lab-fixture and snapshot prerequisites
  cannot be satisfied until Phase 15, so **nothing is `ELIGIBLE_FOR_PROOF` in
  this phase** — the assessment explains exactly what is missing.
  `ELIGIBLE_FOR_PROOF` would mean "a plan may be requested", never that
  execution is authorized or succeeded.
- **Dry run** validates a module's parameter schema, policy and cost **without
  sending any target traffic**.
- **Feature flags** (`services/config.py`): `enable_exploitability_assessment`
  defaults **on** (offline, safe); `enable_lab_checks`, `enable_lab_proof`,
  `enable_guided_sessions`, `enable_lab_terminal` all default **off**. A flag
  alone never approves a job — active capabilities additionally require their own
  plan, attestation, fresh approval and real-lab/recovery gates (Phases 14-16+).
- New API (read/validate only, gated by the assessment flag): `GET /api/proof/modules`,
  `GET /api/issues/{id}/exploitability`, `POST /api/proof/modules/{id}/dry-run`.
  New scans derive assessments automatically after normalization.

## Issue review & remediation (PRD v2 Phase 12)

The canonical issue now carries three **independent** review dimensions (§12.1):
scan observation/change (on the findings), analyst **validation**
(`UNREVIEWED` / `VALIDATED` / `FALSE_POSITIVE` / `INCONCLUSIVE`), and
**remediation** workflow (`OPEN` / `IN_PROGRESS` / `MITIGATED` /
`RESOLVED_VERIFIED` / `RISK_ACCEPTED`). This is the result-quality release gate
before any real exploitation work.

- **Validation confirms the condition/applicability, never exploitability.**
- **Closure is guarded (`services/review.py`):** an administrator can mark
  `RESOLVED_VERIFIED` only with either a *qualifying negative* (the issue is
  actually `NOT_OBSERVED` from the coverage-gated comparison) **or** explicit
  recorded **manual evidence** — a bare clean scan is never sufficient (an
  incomplete stage can produce a false negative). Closure records who/when/
  reason/evidence/method (`RETEST_NEGATIVE` or `MANUAL`).
- **Reopen:** when a previously verified issue is observed again, a new scan
  flips it to `REOPENED` (remediation back to `OPEN`), preserves ownership and
  prior closure metadata, and notifies administrators. Keyed on a newly-created
  occurrence, so re-projecting history via backfill never spuriously reopens.
- **Risk exceptions** (`risk_exceptions`): administrator-only, require a reason
  and an expiry/review date; overdue exceptions are flagged for renewed review.
  Accepted-risk and false-positive issues stay in history/exports; the default
  active count excludes them with a visible excluded total.
- **Redacted JSON export** (`GET /api/targets/{id}/report.json`): preserves
  candidates, excluded dispositions (with totals) and the latest coverage, so
  "what was assessed" and "what was set aside, and why" are both explicit.
  Evidence is the already-bounded summary, never raw payloads.
- New API (all audited): `POST /api/issues/{id}/validate|assign|mitigate`
  (target access), `POST /api/issues/{id}/accept-risk|close` (administrator).

Deferred: a fully detector-version-pinned "focused retest" engine — a retest is
currently a normal compatible rescan whose coverage-gated `NOT_OBSERVED` result
feeds closure; and administrator-set per-target exposure/criticality.

## Offline CVE intelligence (PRD v2 Phase 11)

Candidate CVE correlation, entirely offline. Intelligence comes from a local,
versioned snapshot file (`backend/app/data/vulnintel_snapshot.json`, a sanitized
sample; replace via an administrator import). **No scan performs an online
lookup, and no target IP/hostname/evidence is ever transmitted for enrichment** —
matching is a pure function over product/version strings we already hold.

- **`CandidateAssociation`** (migration `0011`) links a product/version seen on a
  target to a snapshot CVE record. It is **separate from findings/issues** and
  never inflates the actionable finding count — a candidate means "might be
  affected, pending reviewed applicability."
- **Conservative matching** (`services/vulnintel.py`): a version in the affected
  range is `CANDIDATE` (patch/backport state unverified — an upstream version
  never establishes patch state); product-only is `UNKNOWN`; out-of-range is
  `NOT_APPLICABLE` and dropped. Nothing is ever auto-promoted to `SUPPORTED`;
  that requires reviewed evidence (Phase 12).
- **Deterministic priority (§11.1)** — `priority_lane()` returns a lane
  (`VALIDATE_URGENT` / `VALIDATE` / `P1`–`P4`) plus reason codes, never a
  synthetic 0–100 score. KEV candidates → `VALIDATE_URGENT`; other candidates →
  `VALIDATE`; UNKNOWN context → validation, never silently low. Exposure and
  business criticality are administrator-set per target (deferred — default
  UNKNOWN, never inferred from an RFC1918 address).
- **Snapshot freshness** (§9.2): provider, effective date, schema version and a
  stale flag (default 72 h). Missing/failed data is reported as `MISSING`/stale,
  not treated as zero risk.
- **New API:** `GET /api/vulnintel/status` (snapshot freshness),
  `GET /api/targets/{id}/candidates` (candidates for a target),
  `POST /api/admin/vulnintel/refresh` (admin, audited `ENRICHMENT_UPDATED` —
  re-derives from the current snapshot without a rescan, not changing any scan's
  observation time). New scans derive candidates automatically.
- KEV/EPSS/CVSS fields are stored per association. KEV ≠ verified on this target;
  EPSS is 30-day exploitation-activity likelihood for the CVE, not a prediction
  about this asset; absence from KEV is not evidence of safety.

Deferred: administrator-set per-target exposure/criticality fields, frozen
report snapshots, and real NVD/KEV/EPSS import tooling (the snapshot schema and
offline path are in place; only sanitized sample data ships).

## Phase 10 — contextual accuracy (in progress)

First work unit (finding **F1**): `snmp-sysdescr` is **disabled** under the
preserved no-credential-testing boundary (PRD v2 §8.2). It only ever succeeds by
presenting the default `public` SNMP community string, which counts as a
credential probe regardless of Nmap's `safe` category. It is removed from
`nmap.NSE_SCRIPTS` / `_UDP_ONLY_SCRIPTS` so it can never be selected, and
`_findings_for_script` no longer dispatches it. The `nmap.snmp_public_finding`
helper is kept **dormant** (still unit-tested) for a future, separately-reviewed
re-enable. `nbstat` (NetBIOS name disclosure — no credential) stays as the only
UDP-gated script.

Second work unit — §8.4 contextual accuracy fixes:

- **TLS hostname-mismatch is suppressed on IP-only scans** (`httpx.tls_findings`):
  a bare-IP target has no intended hostname to validate the certificate SAN
  against, so `tls-hostname-mismatch` no longer fires for IPs (it still fires for
  hostname targets). The expiring-soon finding is reworded as operational renewal
  guidance, not evidence of compromise.
- **DMARC `p=none` is informational monitoring** (`dnsx.dns_posture_findings`):
  downgraded to INFO and reworded — it is a valid rollout stage, not proof the
  domain is spoofable, and the guidance no longer blindly demands `p=reject`
  before confirming legitimate mail flows pass DMARC. Missing CAA is likewise
  INFO (optional hardening; a parent-domain policy may already apply).
- **Soft-404 / characteristic content:** assessed — the existing exposure
  templates (`env-file`, `git-config`, `phpinfo`, `directory-listing`, the
  default-page detectors) already match on characteristic body content, never
  status-200 alone, so §8.4's requirement is satisfied by design. The bounded
  non-existent-path control for *ambiguous* routes is recorded as a
  template-admission requirement (§8.3) for any future weak-signal detector, not
  a change to the current ones.

Third work unit — more §8.4 context:

- **HTTP security headers** (`missing-security-headers.yaml`): X-Frame-Options
  absence is no longer flagged when a Content-Security-Policy is present (CSP
  `frame-ancestors` is the equivalent control). The template now flags only
  missing `nosniff` *or* missing clickjacking protection (neither CSP nor XFO),
  and its description states absence does not by itself prove XSS/clickjacking.
  Manifest regenerated; `nuclei -validate` passes.
- **SPF qualifiers / malformed** (`dnsx.dns_posture_findings`): distinguishes
  `+all` (permissive), `~all`/`-all` (clean), **multiple SPF records**
  (`dns-spf-multiple`, a RFC 7208 PermError), and **no terminating `all`**
  (`dns-spf-no-all`, INFO — receivers fall back to neutral).
- **RDAP expiry** (`osint.registration_expiry_finding`): reframed as operational
  metadata — past-expiry is MEDIUM (not HIGH) and expiring-soon is LOW (not
  MEDIUM), with wording noting registry renewal/grace/redemption periods mean a
  past date does not prove the domain is re-registrable; verify with the
  registrar first.

Fourth work unit — **per-family capability/coverage surfaced in the UI**: the
scan-detail view now has a dedicated Coverage block per host (see "Coverage
ledger" above), tying the Phase 8 ledger into the frontend so an analyst can see
which check families a scan actually assessed vs. skipped.

Remaining Phase 10 items (DKIM selector handling — already a no-op since we never
brute selectors; and formal reviewed rule-family capability manifests, a §8.3
admission-structure item) are minor/structural and not yet done.

## Canonical issues (PRD v2 Phase 9)

A canonical **Issue** layer now sits above `Finding`, so detectors that find the
*same* condition — including equivalent detectors from different tools — roll up
into one issue per `(target, issue_type)`, while every underlying finding is
preserved as an `Occurrence`.

- **Equivalence is declared, never guessed** (`services/issues.py`). The default
  is tool-qualified (`nuclei:trashscan-git-config-exposure`) so unrelated
  detectors are never merged. The one declared cross-tool class is the TLS
  family: httpx `-tls-grab` and nmap `ssl-cert` deliberately emit the same
  rule-ids, so both collapse to e.g. `tls:tls-cert-expired` on the same surface.
- **Lossless + reversible.** `Issue`/`Occurrence` (migration `0010`) are a
  projection of `Finding`/`FindingSighting`, which are never modified.
  `Occurrence.finding_id` is the legacy alias — an old finding id resolves to its
  canonical issue. `backfill_all()` rebuilds the projection from all existing
  executions and is idempotent (safe to run repeatedly); the migration itself is
  tables-only, so downgrade drops only the projection.
- **New API:** `GET /api/issues` (canonical issues across visible targets),
  `GET /api/issues/{id}` (detail + per-surface occurrence history + the legacy
  finding ids it aliases), and `POST /api/admin/issues/backfill` (admin, audited
  as `ISSUES_BACKFILLED`). New scans forward-derive issues automatically; the
  backfill endpoint projects pre-existing scans.
- Issues UI grouping and issue-level comparison verdicts are the next increment
  (the PRD orders the API before the UI).

## Coverage ledger (PRD v2 Phase 8)

Added a per-execution **coverage ledger** so a "no findings" result can be told
apart from "we never actually checked". Each stage now records a `CoverageEntry`
(`coverage_entries`, migration `0009`) per check-family, written once at
normalization and never updated. The outcome is one of:

- `ASSESSED` — ran to completion; a clean result is a real negative.
- `COMPLETED_WITH_GAPS` — ran but hit a limit (timeout, truncation, budget).
- `NOT_ASSESSED` — did not run: tool missing, nothing in scope, or an
  **exit-zero skip** (a stage that exits clean having assessed nothing is *not*
  a clean negative).
- `INCONCLUSIVE` — ran but completion could not be confirmed.

`services/coverage.py::coverage_outcome()` derives the outcome conservatively
(most-cautious branch first) and is shared by the pipeline and the tests. Each
entry carries a bounded `evidence_ref` (a raw-output file basename, never the
payload).

**Comparison is now coverage-gated:** only a fully `ASSESSED` stage may mark a
previously-seen finding `NOT_OBSERVED`. This closes the gap where a skipped or
incomplete stage could silently "resolve" a real finding — the dangerous
direction of error. Executions recorded before this change (no `coverage` field
in their stage metadata) fall back to the prior ok/incomplete logic.

`GET /api/scans/{id}` returns per-host `coverage`, the scan-detail Stages table
shows a coverage badge (Assessed / Gaps / Not Assessed / Inconclusive), and
(Phase 10) a dedicated **Coverage** block per host lists each check family with
its outcome and reason — making "what this scan actually assessed" explicit,
not just a per-stage badge.

Remaining Phase-8 refinement: an evidence_ref/redaction column on `Observation`
itself (the coverage ledger carries the bounded reference today).

## Tests

The suite is now **257 tests** (Phase 10 added TLS IP-only/DMARC/SPF cases to
`test_enrichment.py` and RDAP-severity cases to `test_osint.py`; Phase 11 added
`test_vulnintel.py` — offline matching range boundaries, product-only UNKNOWN,
the deterministic priority lanes, snapshot FRESH/STALE/MISSING status, and an
end-to-end scan deriving candidates without inflating the finding count; Phase 12
added `test_review.py` — validation/assignment transitions, risk-exception
reason/expiry and overdue expiry, closure refused without a qualifying negative
or manual evidence, reopen-after-verified-closure, scanner-cannot-close, and the
redacted JSON export preserving excluded/candidate/coverage data; Phase 13 added
`test_exploitability.py` — lab prerequisites blocking eligibility, research-only
modules BLOCKED_POLICY, eligible only when all prerequisites satisfied, dry-run
schema validation without traffic, and an end-to-end scan deriving an assessment
that is never ELIGIBLE_FOR_PROOF in this phase; Phase 14 added `test_framework.py`
— the restricted surface has no exec/console/payload methods, unsupported
modules/jobs raise rather than fall back, job-id correlation + idempotency under
lost acks / duplicate delivery, and the conservative verdict interpretation
including Safe-only-conclusive-with-telemetry; Phase 15 added `test_lab.py` — a
fresh fixture is not ready, readiness only after isolation+restore+HEALTHY, a
failed restore records RECOVERY_FAILED and keeps it not-ready, isolation failure
stays not-verified, and exclusive fixture locking; Phase 16 added `test_proof.py` — execution BLOCKED
when the flag is off and when the fixture is not ready, DEMONSTRATED requires
marker echo + negative control, a bare framework success is not demonstrated,
plans are one-shot, and approval requires the exact attestation; Phase 17 added
`test_stream.py` — output sanitization (ANSI/control/HTML), monotonic seq +
reconnect-cursor replay, output not overwriting status truth, transcript-limit
GAP, and a proof attempt emitting durable events).
Post-MVP additions:
`test_passwords.py`, `test_audit_query.py`, `test_scan_targeting.py`, `test_port_sets.py`,
`test_scan_groups.py` (one scan across many targets; one approval; manual start / pause /
stop; passive scans wait for Start too; `GET /api/scans/{id}` surfaces per-host
observations and each stage's `stderr_excerpt`/`note`), `test_enrichment.py` (TLS-posture
and SPF/DMARC/CAA finding rules, end to end through both scan classifications),
`test_osint.py` (crt.sh/RDAP parsing, the off-by-default gate, and the injected-fetcher
adapter path — fully offline), `test_katana.py` (endpoint parsing against katana's
real JSONL shape, profile wiring, and end-to-end through the fake pipeline), `test_nse.py`
(SMB-signing, TLS-expiry, and SMBv1 rule logic; XML parsing of both `<hostscript>` and
per-port `<script>` elements including rejection of any non-allowlisted script id; profile
wiring; end-to-end through the fake pipeline), `test_recon_additions.py` (favicon-hash
observation parsing and its absence when httpx reports no hash; PTR-sweep of a CIDR range
through both the fake adapter directly and a full passive scan execution), `test_udp_scan.py`
(that `snmp-sysdescr` is disabled / absent from the allowlist — PRD v2 §8.2 / F1 — while its
`snmp_public_finding` helper stays dormant but still classifies output; that `nbstat` is only
added to `--script` when UDP scanning is enabled, checked directly against the real adapter's
argv construction with a monkeypatched settings object, not just the fake pipeline; profile
wiring; the fake pipeline emits `nbstat` but never `snmp-sysdescr`; that a `udp_ports` option
overrides `TRASHSCAN_STANDARD_UDP_PORTS` in the real adapter's argv). `test_port_sets.py` and
`test_scan_targeting.py` gained coverage for `PortSet.protocol` (default, explicit `UDP`,
rejection of an invalid value) and for `CreateScan.udp_ports` (recorded on the scan's
approval options, rejected with 422 on a malformed spec, `None` when not specified).
`test_coverage.py` (PRD v2 Phase 8): the `coverage_outcome` mapping (clean →
`ASSESSED`, incomplete → `COMPLETED_WITH_GAPS`, missing tool / exit-zero skip →
`NOT_ASSESSED`, unconfirmed → `INCONCLUSIVE`); that a completed scan writes
`CoverageEntry` rows; and the core guarantee that an exit-zero skipped stage
cannot clear a previously-seen finding. `test_issues.py` (PRD v2 Phase 9): the
equivalence mapping (shared TLS rule-ids collapse across httpx/nmap, unrelated
detectors stay separate); equivalent detectors from two tools rolling into one
Issue with both findings preserved as occurrences; distinct hosts staying
distinct occurrences; and a lossless, idempotent backfill (occurrences ==
sightings, stable across re-runs).

## Concurrency fix

`AuditService.append` now takes a transaction-scoped Postgres advisory lock before
computing the next sequence number, so the API, Celery worker and beat can append
concurrently without colliding on `audit_events.seq` (commit `218e678`). No-op on SQLite
(single-threaded tests).
