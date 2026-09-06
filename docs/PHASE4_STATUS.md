# Phase 4 status — Findings & comparison

## Deliverables (PRD §25, Phase 4)

| Deliverable | Status | Where |
|---|---|---|
| Restricted Nuclei adapter | Done (real, pinned + template allowlist) | `app/adapters/nuclei.py`, `backend/templates/nuclei/`, `backend/templates/nuclei-manifest.json` |
| Finding normalization and evidence | Done | `app/services/findings.py`, `Finding` / `FindingSighting` models |
| Stable fingerprints | Done | `findings.fingerprint()` — target + asset + tool + rule + proto/port + stable evidence key |
| Compatible-baseline logic | Done | `app/services/comparison.py::find_baseline` |
| NEW / STILL_OBSERVED / CHANGED / NOT_OBSERVED | Done | `comparison.compare()` |

**Exit condition — repeated-scan comparison is deterministic and handles incomplete scans:**
`tests/test_findings.py` (12 cases). 70 backend tests pass.

## Nuclei restrictions (PRD §12.5)

- Templates come **only** from `backend/templates/nuclei/` (9 curated non-destructive
  detection templates: default pages, directory listing, exposed `.git/config` / `.env` /
  `phpinfo`, missing security headers, basic-auth prompt, server-version disclosure).
- `backend/templates/nuclei-manifest.json` pins each template's sha256. The adapter runs
  `verify_template_set()` before every scan and **refuses to run** if any file is missing,
  extra, or altered. The Docker build also runs `nuclei -validate` and the manifest check —
  a bad template fails the build. Regenerate the manifest deliberately with
  `backend/scripts/gen_template_manifest.sh` after a reviewed change.
- Invocation: `-disable-update-check -duc` (no template/binary updates), `-no-interactsh`
  (no out-of-band), `-exclude-tags fuzz,dos,intrusive,brute-force,rce,sqli,xss,oast`
  (defence in depth), bounded rate/timeout/retries. No workflows, no user templates.
- Nuclei binary pinned to `3.3.7` and checksum-verified at build time.
- Each finding stores the template id **and** that template's content hash; each execution
  stores `template_set_hash` (SHA-256 over the sorted per-template hashes).

## Findings model

- `Finding` — stable identity per `(target, fingerprint)`. Records source tool, rule id,
  template hash, severity, name, asset, port, matcher, bounded/escaped `evidence_summary`,
  `status` (`OBSERVED` | `NOT_OBSERVED`), first/last seen + first/last execution.
- `FindingSighting` — one row per `(finding, execution)` with the severity and evidence key
  seen in that run; this is what comparison diffs.
- `ScanComparison` — one row per execution: `eligible`, `summary` (counts + by-severity),
  `limitations`, and per-finding `details`. Built automatically when an execution completes.

## Comparison rules

- Baseline = the latest prior **COMPLETED** execution for the same target with the same
  classification. A differing profile is allowed but recorded as a limitation.
- `NEW` (in current, not baseline) · `STILL_OBSERVED` (both, same severity + evidence key)
  · `CHANGED` (both, severity or evidence key differs) · `NOT_OBSERVED` (baseline only).
- **`NOT_OBSERVED` is only assigned when the owning stage (nuclei) completed in the current
  execution.** If that stage failed or was incomplete, prior findings are left unclassified
  and a limitation string explains why (`tests/test_findings.py::test_incomplete_stage_cannot_establish_not_observed`).
- A `NOT_OBSERVED` verdict also flips `Finding.status` to `NOT_OBSERVED` — never to a
  "resolved" state (`FIND-04`).

## Requirements coverage

| ID | Status |
|---|---|
| FIND-01 | Done — assets, services, observations, findings, evidence |
| FIND-02 | Done — source tool, rule/template, severity, target, first/last seen, status, evidence summary |
| FIND-03 | Done — New / Still observed / Changed / Not observed |
| FIND-04 | Done — never presented as verified remediation |
| FIND-05 | Partial — filter findings by severity / status / tool (query params); date/port/service filters pending |
| FIND-06 | Done — bounded raw tool output kept in the per-execution result dir |
| FIND-07 | Done — incomplete stages surface in `stages` metadata and comparison limitations |

## Deferred

- Findings from tools other than Nuclei (httpx TLS/header signals stay observations).
- Headless / multi-step templates (require explicit review per PRD §12.5).
- Report rendering of findings + comparison → Phase 5.
