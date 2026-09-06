# Phase 5 status — Reporting & hardening

## Deliverables (PRD §25, Phase 5)

| Deliverable | Status | Where |
|---|---|---|
| PDF reports | Done | `app/reports/` (Jinja2 `report.html.j2` + WeasyPrint), `POST /api/targets/{id}/reports` |
| CSV exports | Done | `app/reports/csv_export.py` — `scans/assets/services/findings.csv` in a zip |
| Retention cleanup for 7-day data | Done | `app/services/retention.py`, beat task `retention_sweep` |
| Tool/template maintenance workflow | Done | `app/api/maintenance.py`, `MaintenanceProposal` model |
| Backup & restore documentation | Done | [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md) |
| Accessibility & responsive review | Done (pass 1) | skip link, `<main>` landmark, focus styles, non-colour status, reduced-motion, responsive layout |
| Final security & acceptance testing | Done | [`ACCEPTANCE.md`](ACCEPTANCE.md); 83 backend tests |

## PDF report (RPT-01 / RPT-02 / RPT-05)

`app/reports/data.py` assembles every section the PRD §16.1 requires:

1. Branding, target, scope, report time, requester, profiles used.
2. Authorization: for the most recent approved active execution — approving administrator,
   approval time + expiry, approved boundary, resolved addresses, attestation reference and
   text; plus the public-target attestation record when applicable.
3. Executive summary — counts by severity and by comparison classification.
4. Explicit limitations of automated, unauthenticated reconnaissance.
5. Asset inventory — hosts/names, open ports, probable services, web technologies.
6. Findings — severity, asset, evidence summary, first/last observed, source, status; every
   finding labelled as an indicator requiring validation.
7. Change summary against the previous compatible execution (with limitations).
8. Methodology appendix — tool versions, template-set hash, timing, the limits in effect,
   incomplete stages and errors.

## CSV export (RPT-03 / RPT-06)

- Four UTF-8 (BOM) files with `\r\n` line endings, bundled in a zip with a README.
- `csv_export.neutralize()` prefixes any value beginning with `= + - @ \t \r \n` with a
  single quote (`tests/test_reports.py::test_neutralize`, `::test_csv_zip_has_all_four_files_and_escapes`).
- A scanner's export contains only their assigned targets' rows
  (`visible_targets` drives the query).

## Authorization & audit on export (RPT-04)

- `POST` report generation checks target access; a scanner cannot generate for an
  unassigned target.
- Generation writes a `REPORT_GENERATED` audit event; **every download** writes a separate
  `REPORT_EXPORTED` event (`tests/test_reports_api.py`).
- Downloads go through the API (CSRF-checked) as a blob, not a static link, so authorization
  is enforced on each retrieval.

## Retention (PRD §17)

`retention_sweep` (hourly beat, 7-day thresholds):

- `operational_logs` older than 7 days are deleted.
- Read `notifications` older than 7 days after `read_at` are deleted.
- **Audit events are never deleted** — here or anywhere in the application.
- Targets, results and reports are removed only by explicit administrator deletion
  (confirmed, audited, cascades).

Structured operational logs (`OperationalLog`) carry target / execution / stage /
correlation ids and are written by the worker at execution start and completion. They are
never used as a source of truth for authorization or audit history (PRD §31).

## Tool & template maintenance (PRD §12.6)

- `GET /api/admin/maintenance` shows the running tool versions, the reviewed Nuclei
  template set (files + hashes + set hash) and its verification status, and the proposal
  history.
- An administrator files a `MaintenanceProposal` (captures current state + a note);
  approve/reject is recorded as `MAINTENANCE_PROPOSED` / `MAINTENANCE_APPROVED` /
  `MAINTENANCE_REJECTED` in the permanent audit chain.
- Approval returns the operator action: update `backend/Dockerfile` pins (and the reviewed
  templates + `nuclei-manifest.json` if changed), rebuild the worker image, redeploy. The
  application never changes tool or template versions itself, and never for a running
  execution.

## Accessibility & responsive (PRD §14.2)

- "Skip to main content" link; `<main id="main-content">` landmark; `<nav aria-label>`.
- Visible focus outline (3px amber) on every interactive element; `prefers-reduced-motion`
  disables transitions/animations; progress is text, not animation.
- Status is never colour-only — every badge carries its literal label
  (`Pending approval`, `Running`, `Cancelling`, `Timed out`, `Not observed`, …).
- `.sr-only` utility for screen-reader-only text; unread-notification count is
  `aria-live="polite"`.
- Desktop-first layout collapses the sidebar and stacks at tablet width
  (`@media (max-width: 720px)`); wide tables scroll within their card.
- Follow-up (not release-blocking): automated axe/Lighthouse run, full keyboard-trap audit
  of the approval dialog.

## Deferred

- Per-scan ephemeral worker containers and egress enforcement (PRD deferred backlog).
- SSO / MFA, external notifications, signed external audit checkpoints, SIEM.
- Nuclei nmap-version-pinning by tarball checksum (currently the Debian package + pinned
  base image).
