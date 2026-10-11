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
| 10 | Contextual accuracy & detection coverage | `IN_PROGRESS` | F1 resolved (`snmp-sysdescr` disabled). §8.4 done: TLS hostname-mismatch suppressed on IP-only scans + expiry reworded; DMARC `p=none`/missing-CAA → INFO monitoring; soft-404/characteristic-content assessed as already satisfied by the exposure templates. Remaining: header/HSTS-CSP nuance, SPF malformed cases, RDAP grace semantics. 201 tests. |
| 11 | CVE intelligence & priority | `NOT_STARTED` | |
| 12 | Review, focused retest & export | `NOT_STARTED` | Result-quality release gate. |
| 13–24 | Exploitability assessment, Metasploit backend, lab isolation, proof execution, live sessions | `NOT_STARTED` | Each requires its own explicit authorization and (13+) a real-lab gate; fake-backed development only until then. |

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
| 11 | CVE `CandidateAssociation`, KEV/EPSS/CVSS, offline snapshots, deterministic explainable priority | none | New, offline-only (respect F2) |
| 12 | Owner/due-date review, exceptions/expiry, verified closure/retest, redacted JSON export | `Finding.status` only | New review domain + JSON export |

## Exit / handoff (Phase 7)

Current architecture and critical gaps are documented; baseline tests pass
(186 tests as of commit `cdd4d27`). The raw-packet/UDP spike remains
`LAB_PENDING` on the user's lab. No claim is made that prior per-phase status
docs constitute real-lab verification — they record code-gate state only.
