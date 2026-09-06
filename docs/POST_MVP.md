# Post-MVP changes

The five PRD phases (see `PHASE1_STATUS.md` … `PHASE5_STATUS.md`) delivered the MVP. This
document records the changes made **after** that, mostly UX refinements and a few small
capabilities. Nothing here relaxes a scope, authorization, or audit control.

## Schema

| Migration | Adds |
|---|---|
| `0006_port_sets` | `port_sets` table — administrator-defined reusable named port selections |

`alembic upgrade head` (run automatically by `backend/entrypoint.sh`) is at `0006_port_sets`.

## New / changed API

| Method & path | Purpose |
|---|---|
| `POST /api/auth/change-password` | Change your own password (min 12); revokes your other sessions. |
| `POST /api/admin/accounts/{id}/reset-password` | Administrator sets a new password for an account; revokes that account's sessions. |
| `GET /api/findings` | Findings across every target the caller may see, ranked by severity (drives the dashboard). |
| `GET /api/audit/actions` | Distinct audit action types, for the Logs filter UI. |
| `GET /api/audit/events` | Now accepts `action` (repeatable), `q` (free-text over object id / seq / payload values), and `order=asc\|desc`. |
| `POST /api/scans` | Create scans by **either** `target_id(s)` **or** typed `target_value(s)` (host / IP / CIDR). One execution per resolved target; duplicates collapsed. Returns `{"executions": [...]}`. An administrator may create an as-yet-undefined target on the fly (deny rules still apply); a scanner cannot. Active scans accept a `port_preset` and/or `ports` spec. |
| `GET /api/scans/port-presets` | Built-in port presets plus the administrator-defined port sets. |
| `GET/POST/DELETE /api/admin/port-sets` | CRUD for administrator-defined port sets. The spec is validated and canonicalised (`scan_profiles.parse_port_spec`, capped at 6000 ports). |

`POST /api/targets/{id}/scans` is unchanged and still returns a single execution.

## New audit actions

`PASSWORD_CHANGED`, `PASSWORD_RESET`, `PORT_SET_ADDED`, `PORT_SET_REMOVED`. Failed logins
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
  typed list), and type the attestation. Defining a target never queues anything.
- **Your Account** (`/account`, reached from the sidebar) — change your own password.
- **Administration → Port Sets** — define reusable named port selections.
- Page headings and button labels are title case; login shows the raccoon mark centred
  above the card; password fields have a show/hide toggle.

## Tests

The suite is now **115 tests**. Post-MVP additions:
`test_passwords.py`, `test_audit_query.py`, `test_scan_targeting.py`, `test_port_sets.py`.

## Concurrency fix

`AuditService.append` now takes a transaction-scoped Postgres advisory lock before
computing the next sequence number, so the API, Celery worker and beat can append
concurrently without colliding on `audit_events.seq` (commit `218e678`). No-op on SQLite
(single-threaded tests).
