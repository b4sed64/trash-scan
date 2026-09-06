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

- One active scan needs **one** administrator approval covering every target.
- Approval no longer starts the scan. After approval the scan sits in the queue in state
  `APPROVED`; the requester (or an administrator) presses **Start** within the approval
  window (`APPROVAL_WINDOW_MINUTES`, default 120) or it expires. **Stop** cancels the whole
  group — every non-terminal execution.
- Scheduled active occurrences are the exception: the schedule is the standing intent, so
  an approved occurrence starts automatically.
- Passive scans still queue immediately on submit.
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
| `POST /api/scans` | Create **one scan** over any mix of `target_id(s)` and typed `target_value(s)` (host / IP / CIDR); duplicates collapsed. Returns `{"scan_id", "state", "executions": [...]}` — one execution per resolved target, all sharing `scan_id`. An administrator may create an as-yet-undefined target on the fly (deny rules still apply); a scanner cannot. Active scans accept a `port_preset` and/or `ports` spec and need one approval for the group. |
| `GET /api/scans` | Now returns **scan groups** (one row per `scan_id`) with aggregate `state`, `target_count`, per-target `targets[]`, and the group `approval`. |
| `GET /api/scans/{scan_id}` | Accepts a group id (or a bare execution id). Returns the group summary plus `hosts[]` (per-target state, stages, assets, services, findings) and a `summary` block (severity counts, totals, hosts completed) for the per-host review view. |
| `POST /api/scans/{scan_id}/start` | Requester or administrator. Moves `APPROVED` (or passive `DRAFT`) executions to `QUEUED` and enqueues them; 409 if there is nothing to start or the approval window elapsed. |
| `POST /api/scans/{scan_id}/stop` | Requester or administrator. Requests cancellation of every non-terminal execution in the group; 409 if the scan is already finished. |
| `GET /api/scans/port-presets` | Built-in port presets plus the administrator-defined port sets. |
| `GET/POST/DELETE /api/admin/port-sets` | CRUD for administrator-defined port sets. The spec is validated and canonicalised (`scan_profiles.parse_port_spec`, capped at 6000 ports). |

`POST /api/targets/{id}/scans` is unchanged and still returns a single execution (plus its `scan_id`).
`POST /api/scans/{execution_id}/cancel` still cancels a single execution.

## New audit actions

`PASSWORD_CHANGED`, `PASSWORD_RESET`, `PORT_SET_ADDED`, `PORT_SET_REMOVED`, `SCAN_STARTED`,
`SCAN_STOP_REQUESTED`. Failed logins
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
  typed list), and type the attestation. Defining a target never queues anything. The
  chosen targets become **one scan**.
- **Scans → Scan History** lists scan groups. Each has **Start** (once approved) and
  **Stop** buttons and links to a **scan detail** page (`/scans/:id`) with dashboard-style
  severity tiles, a findings-by-severity bar, and a per-host breakdown (state, stages,
  findings, services, assets).
- **Approvals** — one row per scan; multi-target scans show every target and are approved
  once. Approving no longer runs the scan (except scheduled occurrences); the requester
  presses Start.
- **Your Account** (`/account`, reached from the sidebar) — change your own password.
- **Administration → Port Sets** — define reusable named port selections.
- Page headings and placeholder / button labels are title case; the login page shows the
  raccoon poking out of a bin above the card; password fields have a show/hide toggle;
  every page carries a faint raccoon / raccoon-in-a-bin watermark (turned 45° CCW).

## Tests

The suite is now **119 tests**. Post-MVP additions:
`test_passwords.py`, `test_audit_query.py`, `test_scan_targeting.py`, `test_port_sets.py`,
`test_scan_groups.py` (one scan across many targets; one approval; manual start/stop).

## Concurrency fix

`AuditService.append` now takes a transaction-scoped Postgres advisory lock before
computing the next sequence number, so the API, Celery worker and beat can append
concurrently without colliding on `audit_events.seq` (commit `218e678`). No-op on SQLite
(single-threaded tests).
