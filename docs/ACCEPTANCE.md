# MVP acceptance criteria (PRD §24)

Each criterion mapped to where it is implemented and demonstrated. "Test" refers to
`backend/tests/`; run the full suite (317 tests) with `docker run --rm trashscan-api pytest`.
Post-MVP refinements are in [`POST_MVP.md`](POST_MVP.md) and do not change any verdict below.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Clean Docker Desktop can start Trash Scan via documented Compose commands and complete first-Administrator setup | ✅ | `docker-compose.yml`, `README.md`; `entrypoint.sh` runs `alembic upgrade head`; `test_api_authorization.py::test_setup_runs_once` |
| 2 | Administrator configures a private CIDR, creates a Scanner, assigns a target; an unassigned Scanner cannot access it via UI or API | ✅ | `test_api_authorization.py::test_scanner_cannot_reach_admin_routes_or_unassigned_target` (API returns 404, not just hidden UI); `test_scan_targeting.py::test_scanner_cannot_scan_an_undefined_host` (a scanner cannot scan an undefined or unassigned host through `POST /api/scans` either) |
| 3 | A Scanner can run passive discovery immediately on an assigned target | ✅ | `test_api_authorization.py`, `test_executions.py::test_passive_runner_completes_and_normalizes` |
| 4 | No active tool stage starts without a typed attestation and a fresh Administrator approval | ✅ | `test_approvals_api.py::test_active_scan_requires_exact_attestation_and_approval`; `test_active_workflow.py` |
| 5 | An unused approval expires after two hours and cannot be replayed | ✅ | `test_active_workflow.py::test_expired_approval_cannot_start`, `::test_completed_scan_is_not_replayable`; `approvals.py` (409 on re-approve); `lifecycle_sweep` |
| 6 | A started scan may continue after approval expiry but is terminated at its two-hour runtime limit | ✅ | `test_active_workflow.py::test_runtime_cap_times_out_running_scan`; runtime deadline measured from `RUNNING`, independent of approval |
| 7 | Every scheduled active occurrence pauses until separately approved | ✅ | `schedule_service.tick` creates `AWAITING_APPROVAL` + `ScanApproval`, never auto-runs; `test_schedules.py` |
| 8 | Safe and Standard profiles invoke only product-approved options and tools | ✅ | `app/scan_profiles.py` fixed argument allowlist; adapters build argv arrays only; `test_active_workflow.py` |
| 9 | Standard supports SYN and OS detection where Docker Desktop and the lab network permit raw packets | ⚠️ gated | `nmap.py` adds `-sS`/`-O` (and, post-MVP, `-sU` for a fixed UDP port set) only when `TRASHSCAN_ALLOW_RAW_PACKET=1`; disabled by default pending the Phase 0 spike (documented in `PHASE3_STATUS.md`) |
| 10 | Out-of-scope IPs and configured government/military/healthcare deny rules reject execution before tool launch | ✅ | `test_scope_service.py`, `test_api_authorization.py::test_deny_rule_blocks_target_creation`, `test_scan_targeting.py::test_typed_value_hitting_a_deny_rule_is_rejected`; worker `SCAN_SCOPE_RECHECK_FAILED` before any tool |
| 11 | DNS results and redirects are rechecked and cannot expand scope automatically | ✅ | `test_active_workflow.py::test_scope_recheck_blocks_launch_when_domain_leaves_scope`; `test_scope_service.py::test_dns_rebinding_split_answer_denied`; httpx does not follow redirects |
| 12 | DNS wordlist enumeration and every prohibited testing category are absent from routes, UI, worker parameters, and defaults | ✅ | dnsx adapter never passes `-w`/brute flags; Nuclei `-exclude-tags fuzz,dos,intrusive,brute-force,rce,sqli,xss,oast`; no such routes/controls exist |
| 13 | Cancellation and emergency stop terminate the process tree, block downstream stages, retain partial results, reach an accurate terminal state | ✅ | `app/adapters/_exec.py` (process group, SIGTERM→SIGKILL); `test_active_workflow.py::test_emergency_stop_cancels_queued_and_blocks_new`; `test_executions.py::test_cancel_before_start_is_terminal` |
| 14 | Comparable repeated scans produce New / Still observed / Changed / Not observed | ✅ | `test_findings.py::test_repeated_scan_is_still_observed`, `::test_finding_that_disappears_is_not_observed_not_resolved`, `::test_severity_change_is_classified_changed` |
| 15 | Failed or incomplete stages do not incorrectly mark their previous findings Not observed | ✅ | `test_findings.py::test_incomplete_stage_cannot_establish_not_observed` |
| 16 | PDF and CSV exports include only data the requesting user may access | ✅ | `test_reports_api.py::test_report_download_is_authorized_and_audited`; exports scoped by `visible_targets` |
| 17 | CSV export neutralizes untrusted formula-leading values | ✅ | `test_reports.py::test_neutralize`, `::test_csv_zip_has_all_four_files_and_escapes` |
| 18 | Audit verification passes for intact data and fails visibly after a controlled test mutation | ✅ | `test_audit_service.py::test_payload_mutation_is_detected`, `::test_deleted_event_breaks_chain`; `POST /api/audit/verify` raises a high-priority admin notification on failure |
| 19 | No scan automatically downloads a binary or template | ✅ | tools + templates baked into the image at build; `nuclei -disable-update-check -duc`; `subfinder`/`dnsx` `-disable-update-check` |
| 20 | Every execution records pinned versions and a template-set hash | ✅ | `ScanExecution.tool_versions` / `template_set_hash` / `normalized_args` / `parser_version`; `test_executions.py`, `test_findings.py` |
| 21 | The interface passes keyboard navigation, focus visibility, reduced-motion, and contrast checks for core workflows | ✅ pass 1 | skip link, `:focus-visible` outline, `prefers-reduced-motion`, charcoal/off-white palette; automated axe run is a documented follow-up |

Legend: ✅ implemented & tested · ⚠️ gated implemented, disabled by default pending the
Phase 0 network/raw-packet spike.

## PRD v2 release acceptance — Phases 7–23

Phases 7–12 raised result quality (coverage, issue lifecycle, CVE candidates,
review/closure). Phases 13–22 added the exploitability/proof/session capabilities,
**fake-backed and gated off**, each behind its own flag, plan/attestation/approval
and lab/recovery gate. Phase 23 consolidates and publishes the result.

### Capability support matrix

Published at runtime by `GET /api/capabilities` (authenticated), computed from
configuration and fixed build facts — **never from a result**, so no mode is ever
reported enabled because a (fake) result looked successful. `data_provenance`
marks scan data `synthetic` whenever the scanner is not in `real` mode, and the
same block is embedded in `report.json` so fake/demo data is never mistaken for
real findings.

| Capability | Default flag | Backing in this build | Real-lab gate still required |
|---|---|---|---|
| Authorized scanning | on (core) | real adapters; **synthetic in fake mode** | Authorized scan of the supported lab with real adapters; verify coverage + patched negatives |
| Exploitability assessment | `enable_exploitability_assessment` = **on** | offline/analytical | None — no target contact, no execution |
| Active lab prerequisite checks | `enable_lab_checks` = **off** | fake | Active checks against a proven-isolated surface, own plan/attestation/approval |
| One-shot proof / exploitation | `enable_lab_proof` = **off** | fake by default; **real** (Metasploit/`msfrpcd`) when `framework_mode=real` | Controlled one-shot exploit on a registered, isolated fixture with recovery verified; live run against the lab still pending |
| Verified sessions & guided actions | `enable_guided_sessions` = **off** | fake | Internal listener on a proven-isolated topology, verified session, predefined actions |
| Administrator target-session terminal | `enable_lab_terminal` = **off** | fake | Real command-output channel on an admitted, verified session within a granted time |
| External OSINT enrichment | `enable_external_osint` = **off** | real | None — opt-in external lookups |

### Integrated checks performed here (offline/fake)

- **Full suite** green with the fake scanner (`docker run --rm trashscan-api pytest`,
  or `-e TRASHSCAN_SCANNER_MODE=fake`). Running pytest inside the live `api`
  service inherits `SCANNER_MODE=real` and will fail pipeline tests — use fake.
- **Fake/demo data separation** — `test_release_acceptance.py` asserts synthetic
  data is labelled in `data_provenance` and the report export, and that the
  capability matrix mirrors flags only (a flag never makes a fake mode real).
- **Default flags** — the four exploitation/session modes default off; only the
  offline assessment is on.
- **Migration/restore fixture** — the full Alembic chain is reversible on
  Postgres (base→head→base→head, ending at `0020_terminal`), verified on a
  throwaway database so no dev data is touched.

### Real-lab gate (cannot be satisfied in this dev environment)

The end-to-end chain — authorized scan → candidate/assessment → approved proof →
optional verified session → guided actions → evidence → stop/recovery →
remediation/retest, with patched negatives and all enabled mode boundaries — must
be demonstrated on the supported Windows lab. Until then the exploitation/session
modes remain fake-backed and disabled.

**Handoff:** enabled modes (offline assessment, scanning) have test evidence;
disabled optional modes are documented above with their gates. No claim of broad
vulnerability absence or universal exploitability is made.

## PRD v2 Phase 24 — reviewed capability growth (work unit 1: vsftpd)

The framework surface was **widened by explicit administrator decision** to add
authorized isolated-lab exploitation: `run_exploit` / `session_run` /
`session_stop`, served live by `RealMetasploitAdapter` (`msfrpcd`) only when
`framework_mode=real`. The first admitted module is
`exploit/unix/ftp/vsftpd_234_backdoor`.

- **Fake-backed path is tested** (`test_exploit.py`): an exploit that opens a
  session and echoes the per-attempt marker is DEMONSTRATED; a patched/
  non-vulnerable target (the negative control) opens no session and is
  ATTEMPTED_NOT_DEMONSTRATED; the flag-off gate still BLOCKS; the session is
  always stopped; the real backend is selected only by `framework_mode=real` and
  refuses to run without a password; the capability matrix reports `lab_proof`
  backing per `framework_mode`.
- **Still gated:** live execution requires `framework_mode=real` +
  `enable_lab_proof` + verified isolation + a registered fixture, plus the proof
  plan/attestation/approval.
- **Real-lab gate (not yet satisfied):** a live run against the isolated vsftpd
  2.3.4 fixture — exploit → session → benign marker command proving code
  execution → stop/restore — and the patched-control negative. This has **not**
  been run from this environment; CI only exercises the fake backend.
