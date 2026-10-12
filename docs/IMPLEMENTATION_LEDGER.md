# Implementation Ledger (PRD v2 Phase 7 — baseline verification)

This ledger maps the **currently delivered** Trash Scan implementation to the
v2 PRD requirements, records a development-phase status distinct from product
runtime states, and lists the concrete gaps Phases 8–12 must close. It is the
Phase 7 deliverable (`§23.1`, `Phase 7`).

Development-phase states (per `§23.1`): `NOT_STARTED`, `IN_PROGRESS`,
`CODE_VERIFIED`, `LAB_PENDING`, `ACCEPTED`, `BLOCKED`. A fake-adapter
demonstration can reach `CODE_VERIFIED` but never a real-lab `ACCEPTED`.

## Development ledger

| Phase | Title | State | Notes |
|---|---|---|---|
| 0–6 | Baseline recon + enrichment (original PRD) | `CODE_VERIFIED` | Audited below; raw-packet/UDP paths remain `LAB_PENDING`. |
| 7 | Baseline verification & repository plan | `CODE_VERIFIED` | This document. |
| 8 | Coverage ledger & evidence foundation | `CODE_VERIFIED` | `CoverageEntry` + migration `0009`; coverage-gated comparison; 193 tests. Observation-immutability hardening (evidence_ref/redaction column on `Observation`) tracked as a remaining Phase-8 refinement — the coverage ledger carries the bounded evidence_ref today. |
| 9 | Canonical issues, comparison & legacy migration | `CODE_VERIFIED` | `Issue`/`Occurrence` + migration `0010`; explicit equivalent-detector mapping (shared TLS rule-ids collapse httpx+nmap); lossless idempotent `backfill_all`; issue list/detail API + admin backfill. UI grouping deferred to the next increment (PRD orders API before UI). 199 tests. |
| 10 | Contextual accuracy & detection coverage | `CODE_VERIFIED` | F1 resolved (`snmp-sysdescr` disabled). §8.4 done: TLS hostname-mismatch suppressed on IP-only scans + expiry reworded; DMARC `p=none`/missing-CAA → INFO; soft-404 assessed as already satisfied; security-header X-Frame-Options-vs-CSP context; SPF multiple/no-all distinctions; RDAP expiry as operational metadata; per-family capability/coverage surfaced in the ScanDetail UI. Minor remainder: DKIM selectors (already a no-op) + formal rule-family capability manifests (§8.3 structure). 203 tests + frontend build green. |
| 11 | CVE intelligence & priority | `CODE_VERIFIED` | Offline `CandidateAssociation` + migration `0011` (verified applies on Postgres); local versioned snapshot (sanitized sample), conservative matching (CANDIDATE/UNKNOWN only, never auto-SUPPORTED), deterministic §11.1 priority lanes, snapshot freshness, `GET /api/vulnintel/status` + `/targets/{id}/candidates` + admin `vulnintel/refresh` (`ENRICHMENT_UPDATED`). No target data transmitted. 214 tests. Deferred: per-target exposure/criticality fields, frozen report snapshots, real feed import tooling. |
| 12 | Review, focused retest & export | `CODE_VERIFIED` | Issue review columns + `risk_exceptions` + migration `0012` (verified on Postgres). Validation/remediation state machine (`services/review.py`); closure requires a qualifying negative or recorded manual evidence; reopen-after-verified-closure with admin notification; risk exceptions with expiry/overdue; redacted JSON export preserving candidates/exclusions/coverage. 224 tests. Deferred: detector-version-pinned focused-retest engine (retest = compatible rescan today), per-target exposure/criticality. |
| 13 | Module registry & exploitability assessment (offline) | `CODE_VERIFIED` | Reviewed module manifest + `ExploitabilityService` + `ExploitabilityAssessment` + migration `0013` (verified on Postgres). Offline only — no target contact, no execution. Lab-fixture/snapshot prerequisites unsatisfiable until Phase 15, so nothing is ELIGIBLE_FOR_PROOF. Active flags (`enable_lab_*`) default off. 230 tests. **Human review still required to admit real executable module revisions.** |
| 14 | Restricted Metasploit adapter (fake/metadata) | `CODE_VERIFIED` (real-lab gate `LAB_PENDING`) | `services/framework.py`: narrow typed surface (capabilities/metadata/check/job only — no generic RPC/console/payload/module-load/shell), `FakeFrameworkAdapter` + sanitized fixtures, idempotent job correlation, conservative §21.4 interpretation. No real framework, no target contact, no execution. 239 tests. Real RPC behavior + any target-contact check is `LAB_PENDING` and withheld until Phase 15. |
| 15 | Lab isolation, snapshots, health & recovery (fake controller) | `CODE_VERIFIED` (real isolation/restore proof `LAB_PENDING`) | `LabEnvironment`/`LabFixture`/`RecoveryRecord` + migration `0014` (verified on Postgres); `services/lab.py` fake controller + readiness gating + exclusive locks + recovery outcomes; admin API. Fake-backed, no execution. In this env no fixture is ever proof-ready → execution stays BLOCKED. Real provider + on-topology isolation/restore proof + disposable egress-enforced worker remain `LAB_PENDING`. 244 tests. |
| 16 | Approved one-shot proof execution (fake-backed, gated) | `CODE_VERIFIED` (real-lab acceptance `LAB_PENDING`) | `ProofPlan`/`ProofAttempt`/`ProofEvidence` + migration `0015` (verified on Postgres); immutable hashed plan, proof attestation + admin approval, one-shot execution driving the fake framework adapter, nonce-marker evaluator (DEMONSTRATED needs marker echo + negative control), separate proof/recovery outcomes. Hard-gated by `enable_lab_proof` (off) + fixture readiness (false here) → every execution BLOCKED. 251 tests. Real demonstration on a seeded fixture is the `LAB_PENDING` acceptance gate. |
| 17 | Live execution workspace / streaming (fake streams) | `CODE_VERIFIED` | `StreamEvent` + migration `0016` (verified on Postgres); `services/stream.py` durable ordered events, output sanitization (ANSI/control/HTML), monotonic seq + reconnect-cursor replay + GAP, bounded transcript; proof execution emits events; `GET .../events` replay API. No target traffic. 257 tests. Remaining: progressive browser UI + live WebSocket tail. |
| 18 | Session domain, grants & ownership (fakes) | `CODE_VERIFIED` | `SessionGrant`/`LabSession`/`ControllerLease` + migration `0017` (verified on Postgres); `services/session_broker.py`: opaque identity (native-ID reuse across epochs distinct), verify/quarantine, unverified-accepts-no-input, fenced single-writer leases + admin takeover, disconnect stops input. Fake-only, sessions disabled vs real targets; read API behind `enable_guided_sessions` (off). 263 tests. |
| 19 | Internal listener & verified session establishment (fake listener) | `CODE_VERIFIED` (real listener `LAB_PENDING`) | `services/listener.py`: listener-boundary validation (no wildcard/host/loopback/public/out-of-boundary), fake-callback establishment through the broker, fixture-association verify, unexpected-callback quarantine, session-aware parent lifecycle + termination. No socket bound; gated by `enable_guided_sessions` (off). No migration (reuses Phase 18 models). 277 tests. Real listener on a proven-isolated topology is `LAB_PENDING`. |
| 20 | Guided session actions & ownership (fakes) | `CODE_VERIFIED` | `services/guided.py` predefined action registry (whoami / os-context / read-marker / capture-observation / terminate — typed, fixed impls, NO free-form input) + `InteractionRecord` + migration `0018`; lease-gated guarded dispatch, idempotent request_id, per-session budget, OUTCOME_UNKNOWN never auto-resent; lease acquire/heartbeat/takeover + dispatch API. Fake-backed, gated off. 286 tests. |
| 21 | Session transcripts, evidence & recovery reporting | `CODE_VERIFIED` | `SessionEvidence` + migration `0019`; three separated evidence kinds (only PROOF_EFFECT demonstrable), `session_report` separating demonstrated/state/gaps/recovery, absolute+idle expiry + restart reconciliation (orphan→LOST, fixture lock held until recovery), JSON export `sessions` section. Fake-backed. 290 tests. |
| 22 | Optional administrator target-session terminal (fake) | `CODE_VERIFIED` (real channel `LAB_PENDING`) | `services/terminal.py` + `TerminalGrant`/`TerminalFrameReceipt` + migration `0020` (verified on Postgres); administrator-only, behind `enable_lab_terminal` (off). Authorization = grant + controller lease + verified session (NOT a command blacklist); exact attestation, one live grant/session, bounded absolute expiry; frames bounded to 4 KiB, refused frames recorded, deduped by request_id (no replay). Fake channel — accepted input echoes as capability-limited command-output; `capabilities()` discloses no-PTY. 298 tests. A live demonstration is `LAB_PENDING`. |
| 23 | Integrated release acceptance | `CODE_VERIFIED` (real-lab chain `LAB_PENDING`) | `services/capabilities.py` + `GET /api/capabilities` publish the mode support matrix from config/build facts only (no mode enabled by a mock result); `data_provenance` marks synthetic scan data in the matrix and in `report.json` (fake/demo separation). Integrated checks: full suite green under fake scanner, default exploitation/session flags off, Alembic chain reversible on Postgres (base→head→base→head). No new migration. 306 tests. End-to-end real-lab chain is `LAB_PENDING`. |
| 24 | Reviewed module and capability growth — WU1: vsftpd exploitation | `CODE_VERIFIED` (live run `LAB_PENDING`) | Framework surface widened (admin decision) with `run_exploit`/`session_run`/`session_stop`; `RealMetasploitAdapter` (msfrpcd) selected by `framework_mode=real`; admitted module `exploit/unix/ftp/vsftpd_234_backdoor` in the manifest (payload, benign marker, negative control). Wired into the one-shot proof path: exploit→session→marker→stop→recover, DEMONSTRATED only on marker echo. Still gated by `enable_lab_proof` + verified isolation + registered fixture. `pymetasploit3` added (lazy, real-mode only). `test_exploit.py`. 317 tests. Live lab run is `LAB_PENDING`. |

## Requirement → implementation map (original Phases 0–6)

| Area | Requirement | Where implemented | Evidence |
|---|---|---|---|
| Accounts/roles | `ADMINISTRATOR` / `SCANNER`; first-run setup; accounts created disabled; reset revokes sessions | `api/admin.py`, `api/auth.py`, `security.py` | `test_api_authorization.py`, `test_passwords.py` |
| Scope | Allowed private CIDRs + deny-first rules (built-in gov/mil/healthcare); public target needs typed attestation; DNS re-check cannot expand scope | `services/scope_db.py`, `services/scope_service.py`, `models` `PrivateCidr`/`DenyRule` | `test_scope_service.py`, `test_scan_targeting.py` |
| Approval | Active scans need exact attestation + fresh admin approval; one approval per scan group; 2 h window; non-replayable | `api/approvals.py`, `services/scan_groups.py` | `test_approvals_api.py`, `test_active_workflow.py` |
| Lifecycle | `DRAFT→AWAITING_APPROVAL→APPROVED→QUEUED→RUNNING→terminal`; Pause/Stop; emergency stop; 2 h runtime cap; sweeps | `services/execution_service.py`, `worker/runner.py`, `services/emergency.py` | `test_active_workflow.py`, `test_scan_groups.py` |
| Adapters | subfinder, dnsx, nmap, httpx, katana, nuclei, osint + deterministic fakes; mode switch | `adapters/*`, `adapters/registry.py` | `test_parsers.py`, `test_enrichment.py`, `test_katana.py`, `test_nse.py`, `test_udp_scan.py` |
| Results | Asset/Service/Finding/Observation/FindingSighting; stable fingerprint; `ScanComparison` NEW/STILL_OBSERVED/CHANGED/NOT_OBSERVED | `services/findings.py`, `services/comparison.py`, `services/normalization.py` | `test_findings.py` |
| Reporting | Per-target PDF (server-side) + CSV `.zip`; CSV formula-injection neutralized; audit-logged | `services/reports.py`, `api/reports.py` | `test_reports.py`, `test_reports_api.py` |
| Audit | Append-only SHA-256 hash chain; advisory-lock serialized | `services/audit_service.py` | `test_audit_service.py`, `test_audit_query.py` |

## Migration inventory

`0001_initial` → `0002_phase2` → `0003_phase3` → `0004_phase4` → `0005_phase5`
→ `0006_port_sets` → `0007_scan_groups` → `0008_port_set_protocol`. Head is
`0008`; `backend/entrypoint.sh` runs `alembic upgrade head` on start. Phases
8–12 will add forward migrations only (no destructive rewrites, per `§23.1`).

## Reachability / raw-packet capability matrix

| Capability | Flag / gate | Default | State |
|---|---|---|---|
| TCP connect scan (`-sT`), service/version, enrichment | always available | on | `CODE_VERIFIED` |
| Safe/discovery NSE (SMB/LDAP/RDP/TLS config) | profile `nmap_nse_scripts` | on for active | `CODE_VERIFIED` |
| SYN scan (`-sS`), OS detection (`-O`) | `TRASHSCAN_ALLOW_RAW_PACKET` + worker `NET_RAW` | off | `LAB_PENDING` |
| UDP scan (`-sU`) + SNMP/NetBIOS NSE | `TRASHSCAN_ALLOW_RAW_PACKET` + worker `NET_RAW`; Standard active only | off | `LAB_PENDING` |

Host context: Windows 11 + Docker Desktop. Raw-packet capability and the
original cancellation/network spike are **unvalidated on the user's actual
lab** and must stay disabled until the Phase 7 real-lab gate passes.

## Critical findings for Phases 8–12

### F1 — Default-community probe conflict — RESOLVED (Phase 10)

The `snmp-sysdescr` NSE script (added post-MVP, UDP-gated) succeeded by sending
the well-known default `public` read-only community string, surfaced as the
`snmp-public-community-exposed` finding. The v2 PRD's preserved safety boundary
(`§8.2`: "Disable `snmp-sysdescr` under the preserved no-credential-testing
boundary") treats a default-community probe as a credential probe. **Resolution
(Phase 10, first work unit):** `snmp-sysdescr` was **disabled** — removed from
`nmap.NSE_SCRIPTS` / `_UDP_ONLY_SCRIPTS` and no longer dispatched, so it can
never be selected. The `snmp_public_finding` helper is retained **dormant**
(still unit-tested) for a future, separately-reviewed re-enable. `nbstat`
(NetBIOS name disclosure, no credential) remains the only UDP-gated script.

### F2 — Unsafe outbound scope path (track through Phases 10–11)

The external OSINT adapter (`adapters/osint.py`) sends the target domain to
third-party public services (crt.sh Certificate Transparency, RDAP). It is the
only capability that egresses target data off the lab. It is already off by
default (`TRASHSCAN_ENABLE_EXTERNAL_OSINT=false`). Phase 11's CVE intelligence
must stay **offline** (snapshot fixtures, no target data sent); this path is the
reference example of what Phase 11 must not reintroduce silently.

## Gap table → change plan

| Phase | Needed | Current | Gap |
|---|---|---|---|
| 8 | `AssessmentUnit` + immutable `Observation` with per-check coverage, bounded evidence refs/redaction, `COMPLETED_WITH_GAPS`/`NOT_ASSESSED` | **Delivered:** `CoverageEntry` (per-execution/per-family, write-once, bounded `evidence_ref`), `coverage_outcome()` mapping incl. `INCONCLUSIVE`, coverage-gated comparison, API + UI surface. **Remaining:** evidence_ref/redaction column on `Observation` itself (today the ledger carries it). | Mostly closed |
| 9 | Canonical `Issue`/`Occurrence` across tools, equivalent-detector mappings, legacy ID aliases, per-surface baselines | **Delivered:** `Issue`/`Occurrence`, explicit equivalence map, `Occurrence.finding_id` legacy alias, lossless/idempotent `backfill_all`, list/detail/backfill API. **Remaining:** Issues UI grouping; issue-level (vs finding-level) comparison verdicts. | Mostly closed |
| 10 | Correct TLS/DNS/header/**soft-404** interpretation; rule-family manifests; disable credential/community probes (F1) | `tls_findings`/`dns_posture_findings` exist; no soft-404; F1 open | Per-family fixtures; resolve F1 |
| 11 | CVE `CandidateAssociation`, KEV/EPSS/CVSS, offline snapshots, deterministic explainable priority | **Delivered:** offline snapshot + conservative matching + §11.1 lanes + API; no target data sent (respects F2). **Remaining:** per-target exposure/criticality, frozen report snapshots, real feed import. | Mostly closed |
| 12 | Owner/due-date review, exceptions/expiry, verified closure/retest, redacted JSON export | **Delivered:** validation+remediation state machine on Issue, risk exceptions w/ expiry, guarded closure, reopen, redacted JSON export. **Remaining:** detector-pinned focused-retest engine; per-target exposure/criticality. | Mostly closed |

## Exit / handoff (Phase 7)

Current architecture and critical gaps are documented; baseline tests pass
(186 tests as of commit `cdd4d27`). The raw-packet/UDP spike remains
`LAB_PENDING` on the user's lab. No claim is made that prior per-phase status
docs constitute real-lab verification — they record code-gate state only.
