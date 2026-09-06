# Phase 1 status — Foundation

Maps the PRD's Phase 1 exit criteria and the relevant functional requirements to what is
implemented in this repository.

## Phase 1 deliverables (PRD §25)

| Deliverable | Status | Where |
|---|---|---|
| Docker Compose services | Done (api, web, db, redis) | `docker-compose.yml` |
| Local accounts and role enforcement | Done | `app/api/auth.py`, `app/api/deps.py`, `app/services/authorization_service.py` |
| Targets, assignments, private allowlist, public exception, deny rules | Done | `app/api/targets.py`, `app/api/admin.py`, `app/services/scope_service.py` |
| Hash-chained audit events | Done | `app/services/audit_service.py` |
| Seed data and fake scanner adapter | Done | `app/seed.py`, `app/adapters/fake.py` |

**Exit condition — "Backend authorization and scope-boundary tests pass":** 40 tests pass
(`backend/tests/`).

## Functional requirements

| ID | Requirement | Status | Notes |
|---|---|---|---|
| AUTH-01 | Local Administrator and Scanner accounts | Done | |
| AUTH-02 | Enforce role + assignment on every protected backend action | Done | Central `AuthorizationService`; API returns 404 (not 403) for a scanner's unassigned target so existence is not disclosed |
| AUTH-03 | Scanner may list/view/scan/compare/export **assigned** targets only | Partial | list/view/passive-scan enforced; compare/export are later phases |
| AUTH-04 | Admin can disable an account and invalidate its sessions | Done | `PATCH /api/admin/accounts/{id}` revokes all sessions |
| AUTH-05 | Never log plaintext passwords or session tokens | Done | Nothing logs them; audit payloads are scrubbed of `password`/`csrf_token`/… keys |
| AUTH-06 | Record auth success/failure without credentials | Done | `AUTH_SUCCESS` / `AUTH_FAILURE` audit events |
| SCOPE-01 | Configure one or more private IPv4 CIDRs | Done | RFC1918 enforced |
| SCOPE-02 | Public-target creation restricted to admins + checkbox + typed attestation | Done | Exact-string match required |
| SCOPE-03 | Reject active execution outside boundaries or inside a deny rule | Done (logic) | `evaluate_active_scope`; wired to a scope-preview endpoint. No active *execution* exists yet to reject, but the decision function is complete and tested |
| SCOPE-04 | Do not transfer authorization to discovered assets / DNS results / redirects | Done | Discovered assets stored with `approved=false`; scope function ignores them |
| SCOPE-05 | Exact IPv4, IPv4 CIDR, domain, subdomain target records | Done | IPv6 rejected |
| SCOPE-06 | Configurable gov/mil/healthcare + domain/IP/CIDR deny rules | Done | Built-in rules immutable; allow never overrides deny |
| SCOPE-07 | Re-resolve and re-evaluate scope immediately before active execution | Partial | `scope-preview` re-resolves on each call; the "immediately before each active stage" hook belongs to the Phase 3 worker |
| SCAN-10 (partial) | Record tool version | Done for fake adapter | `PASSIVE_SCAN_COMPLETED` records `tool_version` |
| FIND-01 (partial) | Normalize tool output into assets | Done for passive assets | services/observations/findings are Phase 2–4 |
| NOTIF-01 | Dashboard-only notifications + unread count | Done | `app/api/notifications.py` |
| NOTIF-02 | Pending active approvals shown prominently to admins | N/A this phase | no approvals yet |
| RPT-06 | CSV formula-injection escaping | Not yet | Phase 5; helper + test to be added with the export code |

## Audit coverage (PRD §18) implemented now

Authentication outcomes, account creation/enable/disable, assignments, target
create/archive/delete, public-target attestation, private-scope changes, deny-rule
changes, passive-scan completion/failure, audit verification results.

## Explicitly NOT in this phase

Active scan request/approval/execution, attestation form for active scans, Celery worker
and scheduler, approval expiry and runtime enforcement, cancellation / emergency stop,
Nmap / Subfinder / dnsx / httpx / Nuclei adapters and their pinned binaries, findings /
evidence / fingerprints / comparison, PDF & CSV reports, retention cleanup jobs,
tool/template maintenance workflow, TLS/reverse-proxy guidance.

## Known limitations carried forward

- Audit `seq` assignment is only safe for the single-process API. The Phase 3 worker must
  serialize audit appends.
- No transactional outbox yet — add before the worker enqueues real work.
- Public CIDR prefix length is not capped.
- SQLite is used for the test database; production/dev use PostgreSQL. Models avoid
  Postgres-only types so this stays sound.
- `package.json` pins exact top-level versions but no `package-lock.json` is committed yet,
  so transitive npm deps are not locked. Run `npm install` once and commit the lockfile
  before treating the frontend build as reproducible.
