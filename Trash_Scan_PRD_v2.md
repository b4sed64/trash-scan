# Trash Scan — Product Requirements Document v2.2

**Status:** Proposed revision; implementation readiness requires repository review and lab validation.  
**Version:** 2.2  
**Date:** 2026-10-11  
**Source:** User-supplied `Trash_Scan_PRD(1).md`, labeled v1.0 with later implementation annotations.  
**Scope update:** User requested assessment and controlled proof execution, then explicitly requested interactive execution, lab sessions, and staged AI-assisted development. Sections 21–24 define this extension and its delivery gates.  
**Audience:** Student development/security team and AI coding agents in VS Code.  
**Deployment:** Self-hosted Docker Compose on Docker Desktop for Windows; Linux/Kali portability later.

> **Product promise:** Trash Scan inventories an authorized network, detects reviewed vulnerability and configuration indicators, shows what it actually tested, and helps the team validate and remediate findings. An explicitly enabled lab extension assesses exploitability and demonstrates bounded impact through approved proof-of-concept modules.

> **Interpretation rule:** An open service, product fingerprint, vulnerable-version candidate, directly observed condition, and verified remediation are different statements. The interface must preserve those distinctions.

**Reading guide for implementation:** Read sections 3–6 for preserved policy, 7–17 for scan/result correctness, 21 for proof execution, 22 for interaction, 23 for the detailed phase sequence, and 24 for the AI-agent handoff contract. Section 18 is a delivery overview; section 23 owns phase IDs and dependencies. Requirement IDs are stable across revisions.

This is a standalone revision based on the attachment. Recommendations below are proposed product decisions, not claims that code has been changed or existing behavior has been verified. Preserve existing compatible features and data. The attachment's references to delivered phases and repository files are historical claims to verify, not evidence available to this review.

## 1. Executive summary

Trash Scan is a single-team, educational, defensive reconnaissance and vulnerability-assessment dashboard. It coordinates target assignments, passive discovery, active approval, scanner execution, evidence, comparison, review, scheduling, exports, and a permanent tamper-evident audit trail.

Version 2 emphasizes scan/result reliability before adding another scanning engine. The existing bundle—Nmap, Subfinder, dnsx, ProjectDiscovery httpx, Katana, and restricted Nuclei—remains. Results gain a coverage ledger, evidence quality, conservative CVE correlation, cross-tool issue grouping, explainable prioritization, remediation ownership, and focused retesting.

Passive work may run immediately for assigned targets. Every active execution, including a retest or scheduled occurrence, needs a typed attestation and a fresh administrator approval. Approval grants one start within two hours; maximum active runtime is separately capped at two hours. Scanners see assigned targets only.

The baseline scanning profiles remain unauthenticated and non-exploitative. The extension adds offline exploitability assessment, separately approved active prerequisite checks, controlled lab-only proof execution, live execution controls, and explicitly approved guided sessions. An administrator-only terminal is a later gated development phase. It cannot reliably inventory installed patches, validate every CVE, inspect authenticated applications comprehensively, or prove absence of vulnerabilities. Those limits must appear beside results and in reports.

## 2. Review of the supplied PRD

### 2.1 What is already strong

- Explicit authorization, assignments, public exceptions, and allow/deny precedence.
- Separate approval expiry and runtime enforcement.
- Tool/version pinning, subprocess argument arrays, cancellation, and bounded output.
- Historical comparison that avoids equating absence with remediation.
- Structured tool adapters, machine-readable output, parser fixtures, and an audit trail.

### 2.2 Improvements and priorities

P0 means required before trusting the affected result path; P1 means core to the v2 release; P2 means follow-on work. A priority does not authorize prohibited activity.

| Gap in attachment | Consequence | Proposed change | Priority |
|---|---|---|---|
| Only 13 Nuclei templates are described, all info/low | Results emphasize exposure and hygiene; serious conditions may be outside tested coverage | Curated checks with explicit capability coverage; admit safe high-impact detections based on behavior, not severity label | P1 |
| Incomplete stages are recorded, but individual check execution is unspecified | A successfully exited tool can still skip a host/check | Persist per-check outcomes and explicit unknowns; absence classification requires completed comparable coverage | P0 |
| Finding fingerprint includes source tool | Same underlying issue can appear multiple times | Group by canonical issue and affected surface while keeping separate tool observations | P1 |
| No CVE applicability model | A banner or favicon can become a misleading vulnerability claim | Separate product evidence, candidate CVE, applicable conditions, and validation | P1 |
| No triage or remediation workflow | Results become a static list with no owner or closure standard | Assign owner, disposition, due date, remediation note, and targeted retest | P1 |
| Negotiated TLS metadata is used for protocol posture | A normal modern handshake does not establish whether older versions are also accepted | Record what was negotiated; assess protocol support only through explicitly approved bounded tests | P0 |
| Self-signed certificate, missing CAA, DMARC monitoring, and missing headers can be overgeneralized | Lab conventions and legitimate staged policy produce noisy findings | Context-aware rules, effective DNS policy evaluation, and conservative severity defaults | P0 |
| No negative-control requirements for exposure templates | Generic HTTP 200 pages, soft-404s, or login redirects can match | Structural evidence and bounded control requests for ambiguous matches | P0 |
| `snmp-sysdescr` is allowed despite a prohibition on credential testing | Policy contradicts the default-community behavior acknowledged in the attachment | Remove this check from the v2 baseline; no implicit exception for a single default community | P0 |
| Katana's registered-domain boundary is described as sufficient scope | A sibling hostname may be unapproved | Exact approved origins and address binding; validate each outbound destination before contact | P0 |
| Docker/network spike is described as never executed | Unsupported scan modes and unreachable segments can yield misleading coverage | Require a deployment capability matrix and a real lab reachability test | P0 |
| Many numeric budgets remain unspecified | Tool defaults may determine actual traffic and coverage | Explicit conservative proposed limits, measured in the lab before release | P1 |
| Implementation status is mixed into normative requirements | AI agents can treat unverified delivery statements as instructions | Separate this PRD from a repository-backed implementation/acceptance ledger | P1 |

### 2.3 Scope of this revision

The main improvement is trustworthy interpretation, followed by broader approved detection. A larger template count is not a substitute for evidence, coverage, and validation. No second scanner engine is required. The extension introduces a proof runner, restricted Metasploit Framework adapter, and lab interaction broker; it does not change the detection profiles into exploitation workflows. The Metasploit adapter becomes a required component for the framework-backed execution/session phases, with a fake adapter for earlier development. Authenticated patch assessment remains separately scoped future work.

## 3. Goals, non-goals, and baseline decisions

### 3.1 Goals

1. Report tested surfaces and unavailable checks alongside findings.
2. Produce reproducible, evidence-backed detections with measurable false-positive controls.
3. Expand safe detection of material exposures without exploit traffic or credentials.
4. Distinguish technical severity, confidence, CVE applicability, and remediation priority.
5. Track issue ownership, validation, exceptions, remediation, and recurrence.
6. Make comparisons valid at the affected surface/check level.
7. Preserve the attachment's access, approval, scheduling, audit, retention, and deployment model.
8. Assess exploitability and demonstrate a specifically approved effect against a recoverable isolated lab fixture, keeping assessment, attempted execution, demonstrated impact, and recovery separate.
9. Support live output, stop controls, guided session operations, and a separately approved administrator terminal through an authenticated backend broker.
10. Develop major departures from the original PRD in small numbered phases, each with migrations, meaningful verification, and a documented handoff.

### 3.2 Non-goals

Baseline scanners exclude exploitation and payload delivery. Exceptions are reviewed proof actions and approved session transports/interactions in the isolated lab extension in sections 21–22. Credential/default-password/community testing, brute force, directory or DNS wordlists, fuzzing, denial of service, login attempts using credentials, source spoofing, decoys, fragmentation, evasion, persistence, lateral movement, unapproved shells, real-data harvesting, and automated remediation remain excluded across all modes. Reviewed anonymous protocol metadata negotiation, such as LDAP root DSE retrieval without supplied credentials, is permitted only for that narrow purpose; it does not authorize account/access testing. No arbitrary scanner/framework flags, user-authored executable modules, browser execution, external OAST/interactsh callbacks, or uncontrolled target-driven external requests. Section 22 permits only a plan-bound listener/callback inside the isolated lab and an explicitly gated target-session terminal; it does not expose a generic framework console or payload generator. A low request count or GET method alone does not make a check acceptable. A bounded unauthenticated access-control proof may be admitted only against an administrator-seeded non-sensitive lab fixture.

IPv6 active scanning, broad UDP sweeps, screenshots, authenticated scanning, SSO, multi-tenancy, external messaging, per-execution ephemeral containers, and new scanner engines remain deferred. OWASP Amass remains excluded because it overlaps discovery responsibilities. Passive AAAA records may be stored as metadata, but must not trigger IPv6 active traffic.

### 3.3 Preserved baseline

| Decision | Requirement |
|---|---|
| Team | One team, Administrator and Scanner roles |
| Target | Approved private IPv4 ranges; narrow owned public targets by administrator attestation |
| Active approval | Fresh per execution, one-time consumption, two hours to start |
| Runtime | At most two hours from RUNNING; partial results retained |
| Scheduled attestation | Persistent for an unchanged plan; each active occurrence separately approved |
| Visibility | Assigned targets only for Scanners; all targets for Administrators |
| Notifications | Dashboard only |
| Retention | Results until administrator deletion; operational logs seven days; audit permanent |
| Deployment | Docker Compose on Windows Docker Desktop; pinned worker image |
| Exploitation extension | Explicitly enabled for isolated recoverable lab targets only; never inherited from scan approval |
| Interaction | Live output first; guided lab sessions next; administrator-only terminal in a later gated phase |
| Design | Charcoal/forest green/sage/off-white/amber, restrained raccoon accents, literal security language |

## 4. Roles and review permissions

| Capability | Administrator | Scanner |
|---|---|---|
| Accounts, assignments, scope, public exceptions, policy | Manage | No |
| View/search/export targets and findings | All | Assigned only |
| Passive discovery | All authorized targets | Assigned targets |
| Request active scan or retest | Yes | Assigned targets |
| Approve active work and maintenance | Yes | No |
| Cancel scan | Any | Own |
| Emergency stop | Any/all | No |
| Comment, propose validation, remediation, or false positive | All | Assigned targets |
| Confirm validation/false positive/closure or accept risk | Yes | Propose only |
| Assign finding owner/due date | Yes | Propose only |
| Change business criticality/exposure labels | Yes | Propose only |
| Delete results or alter retention | Yes, confirmation and audit | No |
| Register recoverable lab environment and reviewed proof module | Yes | No |
| Request prerequisite check or proof execution | Yes | Assigned lab targets with explicit execution permission |
| Approve proof plan and verify recovery | Yes | Propose only |
| Control guided lab session | Yes, when the approved plan names them | Assigned target plus explicit operator permission and plan grant |
| Observe lab transcript | All authorized lab targets | Assigned targets, subject to transcript visibility policy |
| Use advanced target-session terminal | Explicit terminal grant after terminal release gate | No |
| Transfer session control | Audited takeover/transfer | Release or request control; no forced takeover |

Keep local accounts, Argon2id password hashing, secure HTTP-only cookies, CSRF protection, idle expiration, session invalidation on account disable, and server-side authorization on every API/worker/export path. Never log passwords, cookies, or tokens. Validate permissions again when an export is downloaded. Assignment removal immediately revokes access to related evidence, reviews, notifications, and exports.

## 5. Authorization, scope, and network accuracy

### 5.1 Scope model

Targets support exact IPv4, IPv4 CIDR, domain, and subdomain. Domain scope must separately specify permitted hostnames and address boundaries. A domain record does not authorize every sibling, certificate SAN, CNAME target, shared-hosting tenant, or redirect destination. Public exceptions require administrator checkbox and typed ownership/authorization attestation. Discovered assets remain candidates until independently approved.

Apply configured government/military/healthcare domain/IP/CIDR denials before any allow decision. Sector classification is imperfect; preserve the attachment's disclosure. Deny rules always win.

For each active stage, canonicalize inputs, verify assignment, resolve names through configured resolvers, evaluate every address, and bind connections to validated IPv4 destinations while retaining the approved Host/SNI identity. If a tool cannot enforce the boundary during its own DNS resolution, redirect handling, or crawling, disable that behavior or use a reviewed controlled transport. A pre-launch DNS check alone does not prevent later rebinding.

Same-execution endpoint discovery may supply approved-origin paths to an approved later stage within the reviewed request budget. It must not create authorization for a new origin. Katana's registered-domain default is insufficient: apply exact origin allow rules and validate every outbound request, including redirects. A post-crawl filter cannot undo traffic already sent.

### 5.2 Immutable execution plan

Store the approved boundary, resolved address snapshot, target/policy versions, profiles, port sets, checks and hashes, transport, budgets, resolver configuration, and scanner vantage point. Hash the canonical plan. Approval binds to that hash and is consumed transactionally once.

Any change that broadens hosts, addresses, ports, checks, impact, rate, retries, or runtime requires a new plan, attestation, and approval. At start, revalidate current scope. If required addresses have changed outside the approved snapshot, hold for review rather than silently broadening it. Runtime denies and emergency stop may narrow/stop an existing plan immediately. A scheduled occurrence has its own fresh plan and approval.

### 5.3 Vantage point and capability assessment

Before release, record the real Windows/WSL/Docker/lab topology, worker route/DNS connectivity to each authorized segment, and supported modes. Store a versioned vantage ID with interface/segment identifiers and capability flags; avoid storing unnecessary host secrets.

SYN, OS detection, and curated UDP require the existing `TRASHSCAN_ALLOW_RAW_PACKET` gate and minimum proven capability. Default raw packets remain disabled until the lab spike passes. Unsupported capability is visible as NOT_SUPPORTED, not a silent fallback. Offer a separately approved TCP-connect plan when appropriate. Failure of ping/host discovery must not be reported as proof that a host is absent; a bounded host-discovery bypass may be a reviewed product option, not an evasion control.

## 6. Scan profiles, workflow, and budgets

### 6.1 Profiles

| Profile | Included capabilities | Approval |
|---|---|---|
| Passive | Keyless Subfinder, resolver-based DNS/PTR within bounds, applicable DNS policy analysis; optional external OSINT off by default | No active approval; assignment/scope still apply |
| Safe active | TCP connect against reviewed common ports, bounded service probes/NSE, HTTP/TLS metadata, shallow exact-origin crawl, curated Nuclei checks | Fresh active approval |
| Standard active | Reviewed broader TCP set, SYN/service/OS where supported, narrowly curated UDP, same approved finding policy, deeper bounded crawl | Fresh active approval |
| Focused retest | Selected affected surface and approved detector/dependencies only; no general discovery expansion | Fresh active approval |
| Exploitability assessment | Offline prerequisite analysis of stored evidence and approved module metadata; active checks are separate jobs | Offline analysis needs no active approval; target-contact checks require their own approval |
| Controlled lab proof | One reviewed module, one lab surface, fixed proof behavior, health monitoring, cleanup/recovery | Separate fresh administrator proof-plan approval; section 21 prerequisites apply |
| Guided lab session | Approved session-producing module/transport, internal listener where needed, predefined interaction actions | Session-aware proof plan and explicit operator/action/time grant; section 22 |
| Advanced lab terminal | Terminal input to one established target session; no framework console | Separate administrator terminal grant; disabled until Phase 22 passes |

Safe and Standard may both detect severe conditions when the test itself meets the behavior policy. Standard means broader coverage, not permission for exploit templates. Passive metadata re-evaluation or vulnerability-feed enrichment does not require active approval and must be labeled as analysis of prior observations.

### 6.2 Proposed initial limits

These are product defaults to validate in the lab, not vendor defaults or guarantees. Administrators may lower them. Raising product ceilings requires reviewed configuration, tests, and a new plan where relevant. Profiles must use explicit reviewed numeric port lists; vague labels such as “all common ports” are insufficient.

Proposed Safe TCP list: `22,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5985,5986,6379,8000,8080,8443,9200,27017`. Standard TCP uses a frozen, reviewed list of at most 1,000 ports derived at build time from the pinned Nmap service database, stored as a numeric manifest; it never changes implicitly at scan time. Named administrator profiles may replace these lists within the same ceilings. No arbitrary scanner flags are exposed.

Proposed Standard UDP inventory list: `53,123,137,389,500,4500`. Only approved unicast discovery/negotiation payloads may be used. Defer SNMP and any UDP version probe that inserts a default community. Broadcast/multicast discovery and additional UDP ports require a separately reviewed port/probe manifest; this replaces the attachment's much wider curated default. Record this deliberate reduction in coverage rather than claiming retained SNMP assessment.

| Budget | Proposed starting limit |
|---|---|
| Active executions | 1 globally; 1 per target |
| Active tool stages | Sequential per execution; concurrency reservations consider overlapping assets in different targets |
| CIDR expansion | At most 256 IPv4 candidates per execution; larger boundaries require explicit bounded partitions |
| HTTP traffic | At most 5 requests/s per execution and 2 requests/s per origin, aggregated across tools |
| Total HTTP attempts | 2,000 per execution, including crawler, templates, controls, retries, redirects, favicon |
| DNS | 10 queries/s; at most 2,000 lookups per execution |
| TCP discovery | At most 50 packets/s where the pinned adapter can enforce this; no automatic high-speed fallback |
| UDP discovery | At most 10 packets/s, fixed reviewed unicast ports, no broad sweep or broadcast discovery |
| HTTP timeout/retry | 10 seconds/1 retry; every retry consumes the same budget |
| Crawl | Safe depth 1 and 50 pages/origin; Standard depth 2 and 200 pages/origin; 10 minutes maximum crawl stage |
| Redirects | At most 3, validated before following; cross-origin requires explicit plan authorization |
| HTTP response | At most 1 MiB decoded bytes per response, with wire/decompression limits |
| Stored evidence | At most 16 KiB redacted excerpt per observation; separate bounded structured fields |
| Total retained tool artifacts | 100 MiB per execution; stop collection safely and record truncation if reached |
| Cancellation grace | 5 seconds, then forced process-tree termination |
| Runtime | 2 hours hard maximum |

If an adapter cannot enforce an aggregate budget, serialize origin-specific work under central reservations or disable the unsupported path. Nuclei limits must be explicit; do not rely on its default concurrency/rate. Redirects, retries, template subrequests, and all ancillary traffic count. Reaching a budget is a coverage gap, not a successful negative result. Record actual traffic counters when measurable and estimates with an explicit quality flag otherwise.

### 6.3 User workflow

1. Select target and profile; show planned surfaces, checks, estimated cost, exclusions, and unsupported capabilities.
2. Complete checkbox and typed attestation for active work.
3. Create in-dashboard administrator request containing the immutable plan and impact summary.
4. Approve/deny; approval expires after two hours if unused.
5. Consume once, enter queue, revalidate policy and capacity, and start before expiry.
6. Execute bounded stages; stream stage progress and coverage warnings.
7. Normalize valid observations, assign check outcomes, group issues, enrich locally, compare eligible findings, and publish results.
8. Review, assign remediation, and create focused retest when needed.

Recurring active work pauses for each approval. Missed occurrences expire/deny/cancel or are explicitly rescheduled; never silently catch up. Store schedule timezone and UTC execution timestamps. Configuration changes invalidate persistent schedule attestation.

### 6.4 Lifecycle

Retain DRAFT, AWAITING_APPROVAL, APPROVED, QUEUED, RUNNING, CANCELLING, COMPLETED, FAILED, TIMED_OUT, DENIED, EXPIRED, CANCELLED. Add COMPLETED_WITH_GAPS for an execution that finishes usable work but lacks some approved assessment coverage.

COMPLETED means every required assessment unit has a conclusive outcome for the planned surface; it does not mean every service is reachable or every vulnerability is absent. A closed port can conclusively make a service-specific check not applicable. Unexplained silence, filtering, timeout, skipped templates, or truncated evidence cannot. A fatal worker failure remains FAILED even if partial findings survive.

Cancellation/timeout/emergency stop terminate the whole process tree, block downstream stages and retries, preserve bounded valid partial results, record incomplete units, and produce one idempotent terminal event. Emergency stop blocks future active starts until cleared. Approval expiry after start does not terminate the running job; runtime does.

## 7. Coverage ledger and negative-result semantics

### 7.1 Assessment unit

Persist each planned check/surface pair, or an equivalent lossless compressed representation. A unit contains execution, stage, asset and origin/service, detector ID/version, rule family, applicability, planned budget, execution outcome, timestamps, evidence references, and reason code. Nuclei batch output with no match does not by itself prove each template finished on every host.

| Outcome | Meaning | May establish historical absence? |
|---|---|---|
| MATCH | Completed check observed its condition | No; supports observation |
| NO_MATCH | Applicable check completed, adequate inputs and response, no condition detected | Yes, with comparison prerequisites |
| NOT_APPLICABLE | Completed applicability test excludes the condition; evidence recorded | Only when a rule-specific predicate proves the prior condition cannot apply |
| SKIPPED_POLICY | Policy disallowed check | No |
| NOT_SUPPORTED | Worker/network capability unavailable | No |
| UNREACHABLE | Required service/asset could not be assessed conclusively | No |
| INCONCLUSIVE | Ambiguous response, insufficient evidence, unknown applicability, or missing telemetry | No |
| ERROR | Tool/parser/check failed | No |
| BUDGET_EXHAUSTED | Runtime/requests/bytes/crawl limit prevented completion | No |

Unknown telemetry must produce INCONCLUSIVE. For expensive batch scanning, retain observable completion for checks that matched and conservatively retain unknown outcomes for uninstrumented checks. A focused execution of the exact approved detector can establish a conclusive negative later.

### 7.2 Result summary

Show planned, conclusively assessed, matched, not applicable, skipped, inconclusive, failed, and budget-limited units with counts and drill-down. If a percentage is shown, label it “conclusive planned checks,” define the denominator, and exclude proven NOT_APPLICABLE units. Zero eligible units displays N/A. Never use that percentage as a measure of overall security.

Inventory keeps Nmap's open, closed, filtered, open|filtered, and other native states. UDP silence/open|filtered must remain ambiguous. Host reachability is specific to the recorded vantage point and time. Zero findings with incomplete coverage reads: “No findings detected in the checks completed; coverage gaps remain.”

## 8. Detection program and false-positive controls

### 8.1 Tool responsibilities

| Tool | Role | Boundary |
|---|---|---|
| Subfinder | Public passive name candidates | Keyless reviewed providers; discoveries do not expand scope |
| dnsx | Records/PTR and resolver metadata | No wordlists; internal resolvers; bounded public policy lookups disclosed |
| Nmap | Ports, service/OS estimates, reviewed protocol posture | Explicit scripts/ports only; no category wildcard or broad UDP |
| httpx | HTTP metadata, technologies, bounded favicon/TLS collection | Approved origins/IPs; no automatic SAN/CSP host probing |
| Katana | Linked/static-JS endpoint discovery | Exact authorized origins; no JS execution, forms, upload, or authentication |
| Nuclei | Reviewed condition detection | Immutable behavior-reviewed template set; no unreviewed public templates |

No tool auto-updates or binary/template downloads during scans. OSINT calls to crt.sh/RDAP remain off by default; enabling them discloses target-domain transmission. Disable public discovery for sensitive internal names by default. PTR sweeps remain bounded resolver queries, described as indirect DNS discovery rather than packet-free in every possible resolver topology.

### 8.2 Initial check families

Use these families as acceptance targets rather than an arbitrary number of templates. Each enabled rule must have a positive fixture, negative fixture, applicability predicate, limitations, and remediation guidance.

| Family | Required evidence/interpretation | Default presentation |
|---|---|---|
| TCP/UDP exposure | Port state, protocol, vantage; open port alone is not a CVE | Inventory; policy finding only for an explicit exposure rule |
| SMB posture | Reviewed signing/protocol negotiation outputs; signing enabled vs required distinguished | Configuration indicator; no exploit or credentials |
| LDAP/RDP metadata | Approved root DSE/negotiation output only | Observation or precise posture rule, never inferred account access |
| Exposed configuration/debug files | Specific content structure and control response; HTTP status alone insufficient | Exposure finding; redacted evidence; no use of discovered secrets |
| Exposed source metadata | Valid Git metadata signature; no repository reconstruction | Exposure finding |
| Directory listing | Listing-specific structure, content type, comparison/control where needed | Configuration indicator; do not recursively enumerate files |
| Admin surfaces | Product-specific page evidence | Inventory/info unless an independently observed dangerous condition exists |
| Product/version disclosure | Header/body/negotiation evidence with confidence | Informational observation; input to candidate CVE analysis |
| EOL software | Exact identified version/support branch and dated vendor source | Lifecycle finding; backport/support uncertainty explicit |
| TLS certificates | SAN/validity/chain, correct SNI and trust profile | Separate certificate condition and trust-context finding |
| TLS protocol support | Explicit bounded per-version handshake evidence | Unsupported check stays unavailable; modern negotiation is not comprehensive |
| Web headers/cookies | Correct scheme/content role, header precedence, observed cookies | Contextual configuration indicators; no automatic severe rating |
| DNS/mail policy | Successful complete lookup, effective policy, configured domain role | Contextual policy findings; unknown query result remains unknown |
| Known CVE detection | Approved non-exploit detector or qualified product/version correlation | Direct condition or candidate CVE, clearly labeled |

The existing reviewed NSE candidates include `smb2-security-mode`, `smb-security-mode`, `ldap-rootdse`, `rdp-enum-encryption`, `ssl-cert`, `smb-protocols`, and Standard-only `nbstat` if the actual pinned scripts meet the review policy. Disable `snmp-sysdescr` under the preserved no-credential-testing boundary. Audit scripts and version probes for implicit default-community or credential use; a script's “safe” category is insufficient. Bounded UDP inventory remains possible, with only reviewed non-credential probes.

### 8.3 Template admission requirements

Each manifest entry records detector/canonical issue ID, file hash, tool compatibility, expected product/protocol, fixed allowed methods/paths, maximum requests, response/matcher constraints, prerequisites, impact rationale, evidence/redaction policy, severity rationale, vendor references where relevant, rule version, reviewer, and fixtures.

For detection templates, reject code, headless/browser, workflow chaining with uncontrolled scope, exploit payloads, authentication, credential guessing, fuzzing, OAST, outbound callbacks, uploads/writes, broadcast effects, automatic secret validation, and unbounded enumeration. Proof modules use the separate section 21 admission policy and runner; no exception is inherited by Nuclei or crawling. Even a diagnostic GET can mutate state; explicitly reject logout/delete/trigger/reset/action routes. Crawler link following must use reviewed route exclusions and conservative behavior. A check without enforceable impact or budget semantics stays disabled.

Review high/critical detection templates on their request behavior and evidence; do not enable a template because its CVE is severe or exclude it solely because the condition is severe. “Vulnerability detected” must never imply an exploit was executed.

### 8.4 Common accuracy fixes

- Exposure matches require characteristic content, not just status 200, title keywords, a URL name, or a catch-all body. For ambiguous routes, a bounded non-existent-path control may be approved as part of the detector; it is not a wordlist sweep. Generic login responses and redirects are negative/ambiguous controls. Evidence truncation before the required marker is INCONCLUSIVE.
- Favicon and technology fingerprints are weak product clues and cannot establish version or CVE applicability alone. Store collision/ambiguity notes.
- Do not infer supported legacy TLS versions from a single modern handshake. Persist negotiated version independently. An explicit future protocol-support adapter must be reviewed, budgeted, and tested before enabled; no automatic adoption of `ssl-enum-ciphers`.
- Verify certificate hostname using the actual approved hostname and SAN rules. IP-only scans do not imply a hostname mismatch. Report self-signed separately from untrusted chain; support an administrator-managed lab trust profile. Expiry is a timestamp fact, while impact depends on intended usage. Expiring within 30 days is operational guidance, not evidence of compromise.
- Missing CAA is optional hardening, normally informational; evaluate effective inherited policy before reporting absence. A failed lookup is unknown.
- Evaluate DMARC policy discovery using the current supported standard and versioned parser behavior, including inherited policy where applicable. `p=none` is monitoring, not an invalid record or proof of spoofability. Domain role and declared rollout state inform severity. Do not blindly recommend immediate `p=reject` without assessing legitimate mail flows.
- Parse SPF mechanisms/qualifiers and bounded dependency evaluation; distinguish `+all`, `~all`, `-all`, malformed policies, and DNS errors. Absence of MX alone does not prove the domain does not send mail. DKIM absence is unknown unless selectors are explicitly supplied/known; do not brute-force selectors.
- HSTS applies to HTTPS; CSP guidance depends on browser-rendered content; APIs/non-HTML content may not need the same header set. Evaluate observed cookie attributes without claiming authenticated-session coverage. `X-Frame-Options` absence alone is not a finding if equivalent valid CSP frame restrictions apply. Security-header absence does not automatically prove XSS or clickjacking exploitability.
- RDAP registration dates/statuses may be incomplete or subject to renewal/grace conventions. Treat expiry-related data as operational metadata until the actual condition and source semantics are clear.

## 9. CVE correlation and vulnerability intelligence

### 9.1 Evidence and applicability

Enrichment uses normalized product/version evidence and stored vulnerability records. Model candidate associations separately from canonical issues. Candidate CVEs must not inflate the default actionable finding count.

| Applicability state | Rule |
|---|---|
| CANDIDATE | Product/version suggests a CVE, but one or more prerequisites remain unknown |
| SUPPORTED | Reviewed evidence satisfies documented applicability conditions; no exploit proof implied |
| NOT_APPLICABLE | Evidence excludes the CVE for this surface/configuration |
| UNKNOWN | Record/evidence/matching semantics insufficient or conflicting |

Store vendor/product/version, original evidence and confidence, selected CPE where supported, inclusive/exclusive version ranges, required platform/configuration/components, advisory source, match rationale, and applicability-rule version. Product-only or fuzzy banner matches stay candidates. Evaluate CPE configuration logic rather than flattening all related products into a match. Account for vendor package revisions, backports, reverse proxies, banner masking, and distributions; an apparently old upstream version is insufficient to establish patch state.

Do not attach a generic product CVE list to every open service. Use vendor advisories to resolve applicability/fixed versions where available. NVD CVSS or a template's CVE tag does not prove applicability to this asset. A direct reviewed detection can support a condition without executing an exploit. Unknown patch level remains unknown.

### 9.2 Feed behavior

Use a local cached, versioned knowledge snapshot with optional administrator-enabled refresh/import for NVD, CISA KEV, FIRST EPSS, and reviewed vendor advisories. No online feed lookup is required to complete a scan. Bulk snapshots are preferred; any per-CVE query discloses its destination and transmitted identifiers. Never transmit target IP, hostname, evidence, or secrets for vulnerability enrichment.

Store provider, fetched/effective timestamps, checksum/schema version, record modification time, and missing/stale status. Proposed refresh target is daily, with a visible stale warning after 72 hours for enabled feeds. Respect provider limits and bounded retries. Offline/import mode must remain functional. Missing/failed data is UNKNOWN, not false or zero.

EPSS probability estimates exploitation activity for a published CVE over the next 30 days; it is distinct from severity and does not predict whether this particular asset will be compromised. Store score, percentile, score date, and model version if available. KEV membership means exploitation is known in the wild for that CVE, not that Trash Scan exploited or verified the target. Absence from KEV is not evidence of safety.

A new intelligence snapshot may re-prioritize an existing issue without a rescan. Record this as ENRICHMENT_UPDATED with source dates; do not change the last observation time or fabricate a new scan detection. Freeze report snapshots so later feed changes do not silently alter past reports.

## 10. Result model, evidence, and deduplication

### 10.1 Separate entities

| Entity | Purpose |
|---|---|
| Target | Authorized logical boundary and assignments |
| AssetIdentity | Host/IP identity and time-bounded alias relationships |
| Service/Origin | Protocol/port or scheme/hostname/port; actual destination IP recorded separately |
| AssessmentUnit | Planned check and execution outcome |
| Observation | Immutable, timestamped tool/rule evidence on a surface |
| CandidateAssociation | CVE applicability analysis of product/configuration evidence |
| Issue | Stable underlying security condition on a defined affected surface |
| IssueOccurrence | Per-execution observation and comparison result |
| ReviewEvent | Validation/disposition/owner/comment/severity override history |
| IntelligenceSnapshot | Dated feed data used for applicability and priority |

A template or parser may emit inventory/observations without an issue. A single issue may have multiple observations/tools and multiple candidate CVEs. Separate source output from reviewed interpretation.

### 10.2 Required issue fields

Stable ID; canonical issue family; affected asset/surface; title/category; source severity; normalized severity/rationale; confidence/evidence type; CVE/CWE links where supported; CVSS version/vector/score/source when known; applicability; current observation/comparison/review states; first/last observed; latest assessment attempt/outcome; owner/due date; priority and reason codes; business/exposure context; remediation and safe verification guidance; source references; relevant tool/template/parser versions; evidence references; limitations.

Do not manufacture CVSS for a configuration issue. Keep null for unavailable values. Preserve source severity when a reviewed product severity differs; administrator overrides need reason, actor, and history. Reviewer decisions never rewrite original evidence.

### 10.3 Evidence and confidence

Every actionable issue requires a redacted evidence summary and traceable original observation. Record timestamp, origin/service, connection address, detector/hash, outcome, relevant headers/response/negotiation fields, and applicable limitations. Store both original tool-artifact hash and bounded redacted representation hash where appropriate; do not pretend to retain an original file that was intentionally discarded.

| Confidence | Evidence standard |
|---|---|
| HIGH | Specific reviewed structural/negotiation evidence; required controls passed and applicability established |
| MEDIUM | Several consistent indicators with a material prerequisite or validation gap |
| LOW | Heuristic product clue, generic banner, or ambiguous version association |
| UNKNOWN | Insufficient/conflicting data; no reliable confidence classification |

Confidence describes support for the stated claim. A high-confidence version observation may still yield a low-confidence CVE candidate. Keep those classifications separate. Independent corroboration may improve confidence; duplicate identical banners do not.

### 10.4 Stable identity

Versioned fingerprint: logical target + canonical asset/surface identity + canonical issue key + stable affected location. Source tool, volatile evidence, severity, timestamps, and changing CVE lists are not issue identity. Store tool/template provenance on observations.

Use explicit reviewed mapping for equivalent detector families; do not fuzzy-merge on title. Preserve distinct virtual hosts even when they share an IP. Preserve IP-level and hostname-level claims unless justified identity evidence links them. Group across endpoints only when the rule declares service-wide scope; path-specific exposures remain distinct. Preserve query parameters that identify the resource; redact secrets and normalize only reviewed volatile fields. Do not merge authorization or visibility across logical targets.

## 11. Severity and explainable prioritization

Severity represents technical impact of the supported condition. Confidence represents evidence. Priority represents the next action in the team's context. Display them as separate fields. Candidate CVEs go to a validation queue, even when the associated advisory is critical.

Store CVSS versions independently; do not average incompatible versions or silently substitute zero for missing scores. Business criticality is administrator-set LOW/MEDIUM/HIGH/UNKNOWN. Exposure is administrator-declared or evidenced INTERNAL/INTERNET_EXPOSED/UNKNOWN; an RFC1918 address alone does not establish exposure. Record evidence/time and overrides.

### 11.1 Proposed deterministic policy v1

Policy ordering below is a product proposal to calibrate, not an industry-mandated SLA or probability model. Use rules/reason codes rather than a synthetic 0–100 risk score. UNKNOWN context generates a review task and never silently means low risk.

| Lane / priority | Proposed condition | Expected next action |
|---|---|---|
| VALIDATE_URGENT | Candidate CVE with KEV membership, or candidate critical CVE with evidence of internet exposure | Promptly confirm applicability using approved evidence/manual review |
| VALIDATE | Other candidates, material conflicting evidence, unknown consequential context | Gather missing evidence; retain candidate label |
| P1 — Immediate | HIGH-confidence supported issue: direct material sensitive-data exposure, or applicable KEV issue with internet exposure/HIGH criticality, or supported Critical condition | Assign owner and review promptly; do not automate target changes |
| P2 — High | Other supported High issues; other applicable KEV issues; supported Medium with HIGH criticality and internet exposure; supported Medium with EPSS ≥0.10 and internet exposure | Prioritized remediation/mitigation plan |
| P3 — Planned | Other supported Medium/Low conditions | Address through scheduled maintenance |
| P4 — Informational | Inventory/hardening/lifecycle notes without established material impact | Review context and document disposition |

Evaluate rows in order; retain all triggered reasons. EPSS threshold is configurable/versioned and is not a guarantee. HIGH-impact but MEDIUM-confidence conditions route to validation while preserving their potential severity. Missing intelligence cannot lower a previously known supported severity; show current knowledge limits. Proposed review targets are P1/urgent validation within one working day and P2 within three working days, configurable by the team; no automatic regulatory deadline is inferred.

Accepted risk or false-positive disposition changes the workflow/count view, not detector history or technical severity. Overdue exceptions become visible for renewed review. Show “why this priority” with evidence, context, feed dates, and policy version.

## 12. History, review, remediation, and retesting

### 12.1 Independent states

| Dimension | States |
|---|---|
| Scan observation/change | NEW, STILL_OBSERVED, CHANGED, NOT_OBSERVED, NOT_ASSESSED, REOPENED |
| Analyst validation | UNREVIEWED, VALIDATED, FALSE_POSITIVE, INCONCLUSIVE |
| Remediation workflow | OPEN, IN_PROGRESS, MITIGATED, RESOLVED_VERIFIED, RISK_ACCEPTED |

NOT_ASSESSED means no qualifying later assessment exists. A changed priority due only to intelligence is an enrichment event, not CHANGED detection evidence. Validation confirms the stated condition/applicability, never automatically exploitability. RISK_ACCEPTED requires administrator reason, affected scope, compensating controls where applicable, and an expiry/review date.

### 12.2 Comparison rules

Compatibility is per issue/surface/check: approved scope and asset identity, origin/service/ports, relevant detector meaning/hash, parser/normalization semantics, network vantage, and applicability inputs. Compare unaffected check families when another stage changes. A renamed equivalent detector requires an explicit compatibility mapping; new rules must not make historical absence look like NEW vulnerability introduction without a note.

Use the latest compatible conclusive assessment for the affected issue, not simply the immediately preceding whole scan. An intervening failure neither clears nor hides an earlier finding. Display the baseline date/execution and any gaps. Record the latest attempted assessment separately from last observed and last conclusively assessed.

NOT_OBSERVED requires the same supported detector to conclude NO_MATCH, or a reviewed rule-specific NOT_APPLICABLE predicate with sufficient evidence. Filtering, DNS failure, unreachable service, changed template coverage, parser errors, insufficient telemetry, or budget exhaustion yield NOT_ASSESSED. A confirmed closed/decommissioned surface can support mitigation/closure only under its explicit verification policy and recorded desired state.

### 12.3 Remediation workflow

1. Review evidence and applicability; accept or reject the automated claim with reason.
2. Assign owner, desired state, due date, and remediation/mitigation plan.
3. Record remediation details and external change/ticket reference as plain metadata; no external system write is required.
4. Request a focused approved retest for the affected condition. Reuse the detector version where still allowed; a materially changed detector requires compatibility review.
5. Show NOT_OBSERVED after a qualifying negative. Administrator may mark RESOLVED_VERIFIED only when the retest/manual evidence meets the recorded desired state.
6. Mark a previously verified issue REOPENED when it is observed again; preserve issue identity, ownership, prior closure, and notify the assigned team through the dashboard.

Closing requires an administrator, timestamp, reason, evidence reference, and verification method. If closure is supported only by manual evidence, label it manually verified and retain its provenance. MITIGATED means controls reduce impact without asserting removal of the underlying condition. Historical false-positive/accepted-risk issues remain in exports and history; default active counts may exclude them with visible excluded totals.

## 13. Dashboard, finding detail, and reports

### 13.1 Dashboard

Show pending approvals, running work, coverage gaps, supported actionable issues by priority/severity, CVE candidates awaiting validation, overdue remediation, expiring exceptions, and changes since a visible baseline. Avoid a single “security score,” green clean badges, or rewarding larger finding counts.

Keep inventory, candidates, supported findings, and reviewed dispositions distinguishable. Filters cover target, execution, surface, tool, detector, severity, confidence, applicability, priority, coverage state, review state, owner, date, CVE, and KEV membership. All counts enforce assignment access.

Finding detail shows the precise claim, affected surface, severity/confidence/priority and reasons, evidence, limitations, applicability analysis, source/tool hashes, first/last observed and last attempted assessment, remediation guidance, review timeline, and retest action. Raw evidence uses progressive disclosure, escaped rendering, and redaction.

Design desktop-first, responsive at tablet widths. Preserve keyboard navigation, visible focus, sufficient contrast, reduced motion, and text status markers. Raccoon motifs belong in onboarding/empty states, not severity or authorization language.

### 13.2 Reports/exports

Retain PDF and UTF-8 CSV. Add versioned structured JSON export for AI-assisted review and reproducible integrations, using stable IDs and redacted evidence. No external AI call is made automatically.

Every report includes approved scope, requester/approver/attestation reference, start/end and vantage, actual profile/checks, tool/template/parser/policy/intelligence versions, coverage counts and untested areas, supported findings separately from candidates/info, severity/confidence/priority, known errors/truncation, baseline choices, remediation status, and unauthenticated-assessment limitations. Record the report snapshot timestamp.

Reports must say that zero detected findings does not establish absence of vulnerabilities. Do not silently omit unavailable CVSS/feed values or stale data. Include historical exclusions and manual overrides when relevant. Exports enforce assignments and audit creation/download; formula-leading untrusted CSV cells are neutralized. Escape untrusted report content. Expiring access to a generated download follows account/assignment changes.

## 14. Functional requirements and traceability

All baseline authorization, lifecycle, scope, reporting, auditing, and retention requirements in this document are Must. V2 additions use the following priorities. Requirements with a future capability apply only when that capability is enabled, except explicitly required unavailable-status behavior.

| ID | Requirement | Priority |
|---|---|---|
| V2-SCOPE-01 | Bind every active connection to approved host/origin and validated address; enforce redirects/crawl before contact | Must |
| V2-PLAN-01 | Hash immutable plans; consume one approval transactionally; reapproval for broadened behavior | Must |
| V2-CAP-01 | Display validated network/capability/vantage matrix and unsupported modes | Must |
| V2-COV-01 | Persist planned check/surface outcomes and reason codes, including unknown telemetry | Must |
| V2-COV-02 | Separate clean completion, completion with gaps, fatal failure, and useful partial results | Must |
| V2-COV-03 | Include coverage/untested areas in dashboard, details, PDF, CSV, and JSON | Must |
| V2-DET-01 | Maintain immutable behavior-reviewed rule manifest, bounded requests, and positive/negative fixtures | Must |
| V2-DET-02 | Admit safe serious-condition detections based on behavior, with disclosed family coverage | Should |
| V2-ACC-01 | Implement TLS/DNS/header/soft-404 accuracy rules without unsupported inferences | Must |
| V2-CVE-01 | Separate candidate CVE applicability from supported findings and actionable counts | Must |
| V2-CVE-02 | Use versioned offline-capable knowledge snapshots and preserve unknown/stale states | Must |
| V2-CVE-03 | Enrich CVSS, KEV, EPSS, and vendor fix references with provenance and dates | Should |
| V2-EVD-01 | Require traceable redacted evidence, claim-level confidence, hashes, and limitations | Must |
| V2-ID-01 | Version canonical fingerprints and equivalent-detector mappings; preserve virtual hosts | Must |
| V2-PRI-01 | Display separate severity, confidence, and explainable priority with policy version | Must |
| V2-REV-01 | Audit reviewer decisions, owner/due date, exceptions, overrides, and closure | Must |
| V2-CMP-01 | Compare at check/surface level; unknown coverage becomes NOT_ASSESSED | Must |
| V2-RT-01 | Support focused retest with fresh approval and explicit closure evidence | Must |
| V2-RT-02 | Reopen reobserved verified issues with preserved history | Must |
| V2-EXP-01 | Provide schema-versioned redacted JSON in addition to PDF/CSV | Should |
| V2-MIG-01 | Migrate old findings losslessly and mark unrecorded legacy coverage unknown | Must |
| V2-OPS-01 | Enforce total budgets across retries/redirects/stages and overlapping targets | Must |

## 15. Architecture, data retention, and application security

Retain React/TypeScript/Vite, Python/FastAPI, PostgreSQL, Redis/Celery, pinned Python worker/tool images, Jinja2/WeasyPrint PDF, and Docker Compose. Verify actual repository architecture before modifying it. Do not rebuild a working application purely to match a suggested component name.

Suggested domain services: ScopeService, AuthorizationService, ScanPlanService, CoverageService, ObservationService, IssueService, ApplicabilityService, ComparisonService, PriorityService, ReviewService, and AuditService. Sections 21–22 add LabEnvironmentService, ExploitabilityService, ProofModuleRegistry, ProofPlanService, ProofExecutionService, HealthMonitor, RecoveryService, MetasploitAdapter, SessionService, InteractionBroker, and StreamGateway. Typed adapter inputs/outputs isolate scanner code from persistence models. Migrations add immutable observations, assessment units, stable issues/occurrences, review events, knowledge snapshots, session grants, controller leases, interaction records and transcript events. Use transactions, transactional outbox or equivalent, idempotent jobs, and bounded artifact paths.

Invoke application/scanner executables with argument arrays, no shell interpolation. Prohibit user scanner/framework flags, arbitrary executable/template/output paths, environment overrides, and unreviewed resolvers. Pin dependencies/binaries/templates. Treat XML/JSONL/bodies/headers and terminal output as untrusted; reject unsafe XML entities, bound parse resources/decompression, and sanitize UI/PDF/export output. Untrusted network output cannot change scope or become executable instructions. Target-side proof or terminal activity must come from an explicitly approved action/grant under sections 21–22, never from a tool response or generated recommendation. Terminal input is transported as session data; it must never be interpolated into a local worker shell. Report rendering must not fetch attacker-controlled external URLs.

Preserve persistent database/artifact volumes, least-privilege credentials, secret-free images, and TLS for dashboard access beyond localhost. Keep process/disk/CPU/memory/output limits and backup/restore documentation. Per-scan container isolation remains deferred for baseline reconnaissance. Proof execution requires a separate isolated worker and verified lab network boundary under section 21; sharing the reconnaissance worker for proof execution is not allowed.

Retain normalized results and redacted bounded tool artifacts until administrator deletion; operational logs seven days; notifications seven days after read; permanent audit-linked authorization summaries and audit events. Capture high-risk exposure evidence with streaming minimization: do not permanently retain full `.env` values, credentials, session cookies, private keys, or unnecessary body contents. Preserve structural evidence and a hash where useful. Never test discovered secrets.

Maintain an append-only application hash chain of canonical events with sequence, UTC time, actor, object IDs, prior hash, and current hash. Include plan/coverage changes, feed/rule approvals, normalization migrations, reviews, overrides, closures/reopenings, exports, and deletion. Avoid sensitive evidence in audit payloads. Verify chain and notify on failure. It is tamper-evident under application controls, not tamper-proof against a local administrator.

## 16. Migration and AI implementation instructions

1. Inspect the existing repository, migrations, adapters, manifests, and acceptance records. Map each requirement to VERIFIED_IMPLEMENTED, REQUIRES_CHANGE, NOT_VERIFIED, or DEFERRED. Do not accept the attachment's delivered annotations as proof.
2. Keep existing target/user/scan identities, results, approvals, and permanent audit chain. Add migrations; never rewrite an applied migration or regenerate the chain.
3. Backfill legacy observations/provenance where available. Missing per-check completion becomes UNKNOWN/INCONCLUSIVE. Never retroactively claim coverage or convert legacy absence to verified closure.
4. Introduce canonical issue IDs with alias/mapping records for old finding IDs. Ambiguous duplicate groups stay separate pending review; preserve evidence and dates. Do not merge user visibility across targets.
5. Stage migration against a sanitized backup and verify rollback/recovery. Reports retain original version snapshots; optionally offer clearly labeled reanalysis under new rules.
6. Disable contradictory default-community checks before enabling the new trust model. Fix origin/connection enforcement and accuracy issues before expanding templates.
7. Implement vertical slices with a fake scanner and sanitized fixtures. No real target traffic is needed for parser/UI tests. Require human review of scope, authorization, subprocesses, traffic/capabilities, rule changes, data deletion, and audit code.
8. Do not add a tool/source/template/capability outside the approved manifest. Do not generate an entire replacement application in one change. Every enabled capability needs runnable acceptance evidence.

## 17. Acceptance tests and result-quality evaluation

Tests use owned isolated lab fixtures and approved plans. Scanner and parser fixtures alone establish transformation behavior; real lab tests establish actual traffic, networking, cancellation, and detection.

| Test | Required outcome |
|---|---|
| Unassigned user lists/views/reviews/downloads another target | All backend paths deny; no counts/evidence leak |
| Active scan/retest/scheduled occurrence without fresh approval | No active stage starts |
| Approval replay/expiry and duplicate queue delivery | At most one authorized execution; expired plans do not start |
| Runtime/cancel/emergency stop | Process tree stops, no later traffic/stages, valid partial output, accurate terminal state |
| DNS rebinding, changed addresses, redirect, sibling-host crawl | No unauthorized destination contacted; blocked unit reason recorded |
| Unknown raw-packet support/Windows route issue | Unsupported/unreachable coverage shown; no clean result implied |
| UDP open\|filtered/no response | Native ambiguous state preserved; no claimed open service/absence |
| Tool exit 0 but host/template skipped or no completion telemetry | Unknown/inconclusive check outcome; no historical clearance |
| Previously matched check later times out | NOT_ASSESSED; earlier observation still visible |
| Same check later completes negative | NOT_OBSERVED; reviewer closure remains separate |
| Partial profile overlap | Compare only compatible units; show per-issue baseline |
| Same issue emitted by equivalent httpx/Nuclei rules | One canonical issue, two preserved observations |
| Distinct virtual hosts on same IP | Separate host-specific issues and scope |
| Soft-404, login redirect, generic HTTP 200 | No exposure finding without specific supported evidence |
| Exposed secret-containing lab config | Correct structural match, evidence redacted, no secret use or permanent full-body storage |
| Modern TLS handshake only | Negotiated version reported; unsupported protocol suite remains unassessed |
| Self-signed/internal CA and IP-only TLS scan | Trust profile and name applicability respected; no fabricated hostname mismatch |
| Inherited CAA/DMARC, p=none, SPF error, DNS timeout | Effective policy evaluated; monitoring/errors correctly classified |
| API without CSP, HTML with frame-ancestors | No blanket missing-header vulnerability claim |
| Product/banner/favicon ambiguity; vendor backport | CVE stays candidate/unknown unless prerequisites established |
| Missing/stale KEV/EPSS or offline deployment | Scan completes; provenance warning and unknown values; no implicit zero risk |
| Feed-only priority update | Enrichment event; original evidence/last-observed/report snapshot unchanged |
| Administrator accepts risk/closes; issue recurs | Audit and expiry retained; correct REOPENED history |
| Budget reached inside redirect/retry/template | Counters/bounds respected; completion with gaps, no false negative |
| Legacy migration with incomplete coverage | History preserved, unknown coverage, no automatic closure |
| Malformed XML/JSONL, malicious titles, CSV formulas | Bounded parser behavior, escaped output, no code/formula execution |
| Audit verification and backup restore | Intact chain verifies; controlled mutation fails visibly; restored results/identity consistent |

### 17.1 Quality gates

Maintain a truth-labeled corpus by detector family: positive conditions, legitimate configurations, deceptive responses, missing prerequisites, and failures. Each enabled rule requires at least one positive and one meaningful negative fixture; ambiguous families require the controls in section 8.4. Do not inflate performance by excluding hard negatives from the denominator.

For the controlled corpus, release requires detection of every required known positive, zero known false positives in mandatory negative controls, and zero unsafe absence/closure classifications. Report TP/FP/FN, precision, recall, corpus size, exclusions, and detector version per family; undefined ratios display N/A. This is a regression gate, not a promise of production accuracy. Measure real-world reviewer rejection rate and unassessed-check rate to guide later tuning.

Verify scope boundaries and absence semantics before broader load testing. Submission/approval/cancel acknowledgement remains within two seconds; visible worker updates target five seconds. Cached dashboard API requests target p95 ≤300 ms on a documented local dataset/hardware configuration. No scan-speed claim may override traffic or runtime limits.

## 18. Delivery sequence and exit conditions

The attachment's original Phases 0–6 remain the historical baseline. Their delivered annotations must be verified against the repository; complete missing baseline work rather than rebuilding proven features. Extension phase IDs start at 7. Section 23 provides the authoritative dependencies, AI-sized work units, migrations and acceptance gates; the groups below are navigation only.

| Extension phases | Deliverable | Release gate |
|---|---|---|
| 7 | Baseline/repository audit and missing real Windows lab spike | Evidence-backed implementation ledger and supported topology |
| 8–12 | Coverage, evidence, canonical issues, accurate checks, intelligence, review and exports | Result-quality and migration gates pass |
| 13–14 | Module catalog, exploitability assessment and restricted real framework adapter | Prerequisite and RPC capability contracts verified |
| 15–16 | Isolated lab recovery and approved one-shot proof execution | Real proof, patched negative and verified recovery pass |
| 17 | Live execution workspace and authenticated streaming | Output/stop/reconnect/permission tests pass |
| 18–19 | Session domain/broker, approved listener and session establishment | Exact attempt/fixture association and network boundary proven |
| 20–21 | Guided interactions, control ownership, transcript/evidence, session recovery | Interaction and recovery acceptance pass |
| 22 | Optional administrator target-session terminal | Separate terminal policy/grant/isolation gate passes |
| 23 | Release integration and real lab acceptance | Supported enabled modes pass end-to-end; no mock-only acceptance |
| 24 | Subsequent reviewed module/session capability expansion | Each new action repeats admission and negative-control gates |

Optional explicit legacy-TLS negotiation or new safe CVE detectors ship only after their own behavior review and lab gates. Unavailable checks remain visible; they do not block unrelated truthful reporting. Do not claim release acceptance until the hands-on platform tests have run.

## 19. Risks, tradeoffs, and future decisions

| Risk/tradeoff | Product response |
|---|---|
| Narrow template set misses important issues | Disclose untested families; expand based on lab assets/advisories and safe evidence, not bulk template count |
| Unauthenticated versions cannot prove patch state | Candidate applicability; vendor/backport context; authenticated assessment deferred |
| Strict origin/DNS controls are difficult across CLI tools | Capability-check adapters; fail closed for unsupported paths; do not rely on output filtering |
| Accurate per-check telemetry costs time/storage | Lossless compressed ledger, bounded batches, unknown outcome when telemetry absent |
| Crawling read-only pages may still cause side effects | Reviewed route exclusions, small budgets, no forms/browser/actions; disclose unavoidable residual application behavior |
| High-impact templates can be intrusive | Review actual behavior and evidence; severity alone is not a safety classification |
| Private lab certificate/DNS conventions create noise | Trust/domain-role context; inherited policy; conservative informational defaults |
| Old issue identity and new deduplication conflict | Versioned mapping and human review of ambiguous merges; never erase observations |
| Persisted evidence may contain secrets | Capture-time redaction/minimization, bounded storage, no validation/use of secrets |
| Intelligence gets stale | Snapshot timestamps, offline mode, stale warnings, never fake freshness |

Before implementation, validate the proposed budgets and priority policy against the actual lab's size and service mix. The revision explicitly changes the original no-exploitation boundary only for the controlled lab extension and approved interaction in sections 21–22. The no-credential-testing boundary remains. Authenticated patch/configuration assessment, an additional dedicated scanning engine, or credential-based inventory requires its own product decision and authorization model; it is not included here.

## 20. Official reference notes

Reviewed on 2026-10-11. These references explain tool/protocol behavior; the requirements and default thresholds above are proposed Trash Scan design choices. Pin the actual selected tools and record exact compatible behavior during implementation.

1. [Nmap port states](https://nmap.org/book/man-port-scanning-basics.html) and [UDP ambiguity](https://nmap.org/book/scan-methods-udp-scan.html): port states are vantage-dependent; silence can mean open or filtered.
2. [Nmap snmp-sysdescr](https://nmap.org/nsedoc/scripts/snmp-sysdescr.html) and [SNMP library](https://nmap.org/nsedoc/lib/snmp.html): script classification does not replace a review of community/credential behavior. The source attachment itself acknowledges its default-community exception; v2 removes that exception.
3. [Nuclei running and rate controls](https://docs.projectdiscovery.io/opensource/nuclei/running): concurrency and rate controls must be explicitly selected for the pinned release.
4. [Katana official repository](https://github.com/projectdiscovery/katana): the default registered-domain scope differs from an exact approved origin.
5. [httpx usage](https://docs.projectdiscovery.io/opensource/httpx/usage): distinguish TLS metadata/probing features; never let discovered certificate or policy names expand authorization.
6. [NVD Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities): CVE configuration/CPE matching requires structured applicability handling.
7. [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): known exploitation informs prioritization; it does not establish target applicability.
8. [FIRST EPSS interpretation](https://www.first.org/epss/using-epss): probability of exploitation activity is distinct from severity and target-specific compromise probability.
9. [FIRST CVSS v4 specification](https://www.first.org/cvss/v4.0/specification-document): preserve score/vector/version/source rather than inventing an undifferentiated risk score.
10. [SPF RFC 7208](https://www.rfc-editor.org/info/rfc7208/): policy parsing and bounded DNS mechanisms must distinguish qualifiers and error outcomes.
11. [CAA RFC 8659](https://www.rfc-editor.org/info/rfc8659/): effective issuer policy can be inherited up the DNS name tree; absence is not automatically a vulnerability.
12. [DMARC RFC 9989](https://www.rfc-editor.org/info/rfc9989/): current standard reviewed for policy discovery/monitoring behavior; it obsoletes RFCs 7489 and 9091. Record standards/parser version and test existing-domain compatibility rather than assuming older policy-discovery logic remains complete.
13. [Metasploit Framework RPC API](https://docs.rapid7.com/metasploit/rpc-api/): a proposed adapter can use a structured backend integration. The framework's broader capabilities are not product permissions; the adapter exposes only reviewed module operations.
14. [Metasploit check-method semantics](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-write-a-check-method.html): a module's check can use heuristic or active evidence. Do not treat the check operation as inherently harmless or translate a framework result into global asset safety.
15. [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final): assessment planning and rules of engagement provide context for the engagement records below. Trash Scan's numerical limits and approval/recovery design are product requirements, not a claim of NIST certification.
16. [Metasploit standard API reference](https://docs.rapid7.com/metasploit/standard-api-methods-reference/): structured module/job/session operations provide the framework side of the adapter. Verify methods and result semantics against the pinned Framework revision; this documentation also covers product editions and is not proof of feature parity. Framework RPC credentials are privileged; application roles and action restrictions belong in the broker.

## 21. Exploitability assessment and controlled lab proof

**Scope decision:** Assessment/planning and bounded proof execution are included following the user's explicit request. Section 22 adds the subsequently requested interaction modes and supersedes the earlier v2.1 blanket exclusion of interactive sessions. Sections 21–22 together define the sole exception to the baseline no-exploitation rule. They specify product behavior, not authorization to attack a particular target.

### 21.1 Modes and eligibility

| Mode | Behavior | Required authorization |
|---|---|---|
| Offline assessment | Associate stored evidence with reviewed modules; identify satisfied, missing, contradicted, and stale prerequisites | Assignment access; no target contact |
| Active prerequisite check | Execute the exact reviewed check operation for one module/surface | Separate active-check plan, attestation, fresh approval |
| Controlled proof | Exercise the condition to demonstrate a fixed benign effect on a registered lab fixture | Separate proof plan, attestation, fresh administrator approval, lab/recovery gates |
| Session-producing proof | Establish the declared lab session/transport and validate its fixture identity | Session-aware proof plan including any internal listener, operator/action grant and time bounds |
| Guided session interaction | Execute predefined reviewed validation operations on that verified session | Active session grant and exclusive controller lease; section 22 |
| Advanced lab terminal | Interactive input to one target session | Separate administrator terminal grant and completed terminal phase |

An ordinary scan or retest approval never authorizes proof execution. Offline analysis can run automatically after normalization; a finding or assessment cannot automatically request or initiate an active check or proof. After deliberate submission and fresh approval, the worker may launch that exact job within its approval window. No auto-exploit, exploit chaining, automatic retry, or recurring proof schedules. An operator selects and submits each proof deliberately.

Proof targets must be isolated, non-production, explicitly registered lab fixtures owned/controlled by the team, with recoverable known state and no real secrets or personal data. Private addressing alone is insufficient. Public targets, shared infrastructure, production-adjacent workloads, fragile systems, and targets whose isolation/recovery cannot be verified are ineligible. Existing public-target scan attestations never grant proof eligibility.

The UI must show permitted lab surfaces and proof mode separately from ordinary scan targets. Proposed feature flags are `TRASHSCAN_ENABLE_EXPLOITABILITY_ASSESSMENT=true`, `TRASHSCAN_ENABLE_LAB_CHECKS=false`, `TRASHSCAN_ENABLE_LAB_PROOF=false`, `TRASHSCAN_ENABLE_GUIDED_SESSIONS=false`, and `TRASHSCAN_ENABLE_LAB_TERMINAL=false`. Enable offline assessment as part of the extension; gate active capabilities behind administrator-controlled feature flags and their release acceptance. Feature enablement alone does not approve a job. These names/defaults are proposed requirements, not verified existing settings.

### 21.2 Components

| Component | Responsibilities | Delivery requirement |
|---|---|---|
| ExploitabilityService | Evaluate product/build/configuration prerequisites and evidence age; explain uncertainty and map issue to approved module | Must |
| ProofModuleRegistry | Immutable reviewed manifests; checksums, dependencies, compatibility, impact, proof and cleanup contracts | Must |
| Engagement/ProofPlanService | Exact lab target, module/action, operator, effect, budgets, stop/recovery rules, plan hash, approval | Must |
| LabEnvironmentService | Bind target to fixture identity, network boundary, target image/build, baseline health and snapshot | Must |
| Restricted framework adapter | Metasploit Framework integration via private structured RPC; exact admitted operations only | Must for framework execution/session phases; fake adapter used earlier |
| ProofExecutionService | Isolated worker, one-time launch, bounded lifecycle and optional approved session handoff | Must |
| HealthMonitor | Check approved health signals, detect damage/unknown health, stop execution and lock the target | Must |
| RecoveryService | Track fixed artifact cleanup and approved snapshot restoration/manual recovery; verify readiness afterward | Must |
| ProofEvidence/Reporting | Correlate nonce-bound effect to execution; preserve limitations, failed attempts and recovery history | Must |
| Operator planning view | Show prerequisites, expected impact, unavailable modules, evidence gaps, costs and proposed next action | Must |
| SessionService/InteractionBroker | Verified session binding, grants, leases, predefined actions and separately granted terminal mode | Must for interaction |
| StreamGateway | Authenticated sequenced output/status to browser; permission checks, bounded buffers and reconnect | Must for live workspace |

Do not import or expose an entire exploit catalog. A module may be visible as a research reference without being executable. Record licensing/source attribution, pin framework/dependencies, and review modules at exact revisions. Module availability or framework reliability rankings do not establish impact safety or applicability. The first release must admit and demonstrate at least one genuine fixed-effect proof against a seeded lab fixture; mock adapters alone do not satisfy this gate.

The Metasploit adapter is a backend bridge, not permission to expose every framework feature. Keep RPC credentials server-side and RPC reachable only inside the restricted worker boundary, using authenticated protected transport. Expose typed catalog/check/proof/job operations, then the explicitly admitted session read/action/stop operations in section 22. Prohibit generic RPC, framework console commands, arbitrary datastore options, unrestricted payload generation, module loading, resource scripts and automatic fallback through the application. A target-session terminal is available only under section 22's separate grant and gate; it does not expose the framework console. Verify exact capabilities for the pinned revision; missing support is unavailable, not a console fallback.

### 21.3 Module admission manifest

Each admitted action, including a framework check, needs its own reviewed contract. At minimum store:

- Stable module/action ID, source/license, source hash, framework/dependency/image digests, reviewer, review date, and admission/disabled state.
- CVE/canonical issue mapping and the precise claim the action can support.
- Compatible target product/build/architecture/configuration, required service and protocol, and all applicability prerequisites.
- Check classification: metadata-only, active read-only, or potentially state-changing. An operation named `check` is not automatically read-only.
- Allowed typed inputs and fixed internal options; exact target count/origins/ports, maximum requests/bytes/retries, and runtime ceiling.
- Expected effect, maximum permitted side effects, proof evaluator, negative control, evidence/redaction fields, and session/listener behavior.
- Lab fixture/build identifier, approved isolated topology, clean/patched fixture results, health signals and stop thresholds.
- Fixed created-artifact inventory, cleanup procedure, snapshot/recovery procedure, restoration blast radius, and recovery verification.

Review action code and dependencies rather than trusting labels or CVE severity. Admit only actions whose outputs, destinations, resource use, and declared effects are understood and bounded by the selected mode. Exclude production data, credential material, unapproved shells/agents, persistence, lateral movement, credential theft/testing, destructive writes, crashes as proof, denial of service and external callback services. Session-producing transports must be separately admitted under section 22 and must not enable automatic follow-on actions. Do not automatically download a PoC from an advisory, paste executable research content into the runner, or permit user-uploaded executable modules.

One-shot proof execution returns a fixed marker or similarly bounded result and exits; operators cannot substitute arbitrary proof commands/payloads. A later admitted module may establish an approved session under section 22. Guided session actions stay predefined; free-form target-session input is confined to the separately gated administrator terminal. An access-control/read/write proof may use only administrator-seeded non-sensitive fixture data or a disposable named marker resource. Declare any such write and cover it with cleanup/recovery. No real secret access, bulk reads, repository reconstruction, or target-data exfiltration. Session callbacks/listeners stay inside the exact isolated lab boundary, never public/external services.

### 21.4 Assessment and prerequisite checks

Assessment output contains matched evidence, module-compatible builds, each prerequisite's state and provenance, freshness deadline, exclusions, expected effect/impact, and next allowed action. Use SATISFIED, MISSING, CONTRADICTED, UNKNOWN, and STALE per prerequisite. Derive ELIGIBLE_FOR_PROOF, NEEDS_EVIDENCE, INCOMPATIBLE, or BLOCKED_POLICY separately from CVE applicability and confidence. ELIGIBLE_FOR_PROOF means the plan may be requested, not that execution succeeded or is already authorized.

Suggested prerequisite evidence includes target build/architecture, expected configuration, reachable approved service, fixture identity, lab network isolation, current snapshot/restore readiness, and action-specific conditions. A favicon, version banner, KEV entry, public PoC link, or another tool's finding cannot independently establish eligibility. Unknown consequential prerequisites block launch. A module without a check operation may become eligible through other reviewed prerequisite evidence; never fabricate a successful check.

A dry run validates metadata, parameter schemas, policy, and cost without sending target traffic. Active checks require approved typed action parameters and their actual impact contract. A potentially state-changing check uses proof-level lab/recovery gates and approval even if the framework calls it a check.

Preserve raw framework outcomes. For Metasploit integration, map version/heuristic `Appears` to candidate evidence, `Detected` to product/service evidence, and `Vulnerable` to its reviewed condition evidence; none automatically means demonstrated impact. `Safe` becomes a conclusive condition negative only if telemetry proves the relevant service was reached and the intended check completed sufficiently. Otherwise it remains inconclusive. `Unknown`/`Unsupported`, absent results, timeouts, and errors cannot establish absence. These are product interpretation requirements, not replacements for the framework's native result semantics.

### 21.5 Proof plan and execution flow

1. Operator chooses one issue, one fixture surface and one admitted module/action; sees prerequisite gaps and expected effects.
2. Resolve gaps through offline evidence/manual lab records or a separately approved active-check job. Requesting a check does not implicitly request exploitation afterward.
3. Create a proof plan that binds exact fixture identity/build, validated IPv4/origin/port, action/options and hashes, fixed proof behavior/evaluator, health monitors, budgets, cleanup/recovery steps, snapshot identity, operator, and end time. Store engagement purpose/authorization reference, exclusion boundaries and administrator review.
4. Reconfirm the lab has no non-target connectivity, prepare the recoverable baseline, and record the actual snapshot/state digest after preparation. External snapshot management uses a separate administrator/provider credential; no target credential testing is introduced.
5. Requester checks and types the proof-specific attestation acknowledging the exact permitted effects. Administrator reviews both the proof and recovery blast radius and approves/denies the immutable hash. Changing module/effect/target/build/snapshot/options/budgets requires a new plan and approval.
6. Consume approval once; reserve an exclusive fixture/environment lock; verify scope, operator access, module not disabled, evidence freshness, clean baseline health, unchanged build/snapshot, and worker/network readiness immediately before launch. Stale or changed prerequisites hold/expire the plan rather than silently proceed.
7. Run once; collect bounded evidence and monitor health. For a session-producing plan, verify and hand off only the declared session under section 22. Stop on scope violation, health degradation/unknown state, budget exhaustion, cancellation, permission/policy revocation, or undeclared process/session/artifact. Do not retry a failed/uncertain proof automatically.
8. Evaluate the declared proof predicate. Preserve negative/ambiguous evidence as attempt outcome; a zero exit code is not proof.
9. Stop all activity, run only the approved fixed cleanup/recovery, and verify lab readiness. Record proof outcome separately from recovery outcome. Recovery confirmation cannot erase demonstrated evidence.
10. Publish evidence and remediation/verification guidance. Require a fresh plan/approval for another attempt, different effect, changed module, or later proof retest.

Approval retains the two-hour one-start window. Proof budgets are shorter than reconnaissance: proposed maximum one active proof globally, one module/target per job, one attempt, 60 seconds per prerequisite-check action, 120 seconds proof execution, and ten minutes total managed lifecycle including preflight, monitoring, cleanup and verification. The worker cannot extend them silently. Module manifests specify lower request/byte/time bounds when needed. Each module must declare a concrete health-poll interval no slower than two seconds where supported. If a shorter guaranteed monitoring/stop bound is needed and unavailable, reject the module.

Those durations apply to one-shot plans. A session-producing plan has section 22's explicitly approved establishment, session and total-lifecycle limits; it must not silently reuse/extend a one-shot plan. An active interactive session occupies the same exclusive proof/fixture capacity until termination and verified recovery.

The ten-minute deadline never means recovery completed. At deadline, isolate and halt the execution worker, persist incomplete/failed recovery, and keep the fixture locked for administrator recovery. A preapproved out-of-band recovery operation may restore only the recorded fixture snapshot under its recorded provider boundary; broad hypervisor restoration or deleting unrelated resources is forbidden. Further recovery activity remains visible and audited outside the terminated proof attempt.

### 21.6 Worker and target recovery boundaries

Use a separate ephemeral proof worker with minimal capabilities, no host/Docker socket mount, no user credentials, no shared production volumes, and no unrestricted internet route. Enforce exact target/service egress and prohibit access to other lab targets, application/database services, host management networks and external destinations. A required orchestration/monitoring channel must use a narrow authenticated control path; it must not grant the module general management-network reachability. Run framework instances/jobs within this disposable boundary or an equivalently verified isolated VM. Docker Desktop deployment must demonstrate these boundaries on the actual Windows topology before enablement.

Worker destruction stops worker processes, not target-side effects. The lab fixture itself must be disposable or have a tested snapshot/restore path. Initial targets use a single-fixture recovery boundary; reject a snapshot whose restoration could overwrite unrelated/shared workloads. Snapshot presence alone is insufficient: record a successful restore rehearsal for that fixture version, health checks, and administrative capability to restore it. Module execution cannot provision a broader privileged worker to bypass isolation.

Health state is HEALTHY, DEGRADED, UNKNOWN, or RECOVERY_REQUIRED. Store baseline/post-check results and expected thresholds, not just a ping result. Loss of monitoring triggers stop and RECOVERY_REQUIRED. Cleanup tracks known proof artifacts; unexpected state requires recovery review. A recovery failure sets RECOVERY_FAILED and blocks subsequent active work on that fixture until an administrator verifies readiness. A successful proof with failed recovery remains a successful proof plus an unresolved recovery incident.

Emergency stop terminates proof workers and blocks new starts; it cannot promise instantaneous reversal of target changes. Surface requested, confirmed, and failed stop separately. On worker/API restart, reconcile persisted job and fixture-lock state; never assume the target is clean from a missing process. An administrator may retain the stop condition while performing bounded approved recovery.

### 21.7 Evidence, results, and data model

Record proof attempt ID, target/fixture/build identity, related issue/CVE and prerequisite snapshot, engagement/authorization reference, immutable plan/approval, module/action/image hashes, operator/vantage, begin/end, health observations, traffic/runtime bounds, proof evaluator version, original tool result, redacted evidence, declared/observed effects, stop reasons, cleanup artifacts and recovery verification. Add LabEnvironment, FixtureBaseline, ModuleRevision, ExploitabilityAssessment, ProofPlan, ProofAttempt, ProofEvidence, and RecoveryRecord entities. Existing finding observations remain immutable.

| Proof outcome | Meaning |
|---|---|
| DEMONSTRATED | Nonce-correlated evidence satisfies the reviewed fixed-effect predicate on the exact fixture |
| ATTEMPTED_NOT_DEMONSTRATED | The planned attempt completed adequately but did not prove its effect; it does not establish non-exploitability |
| INCONCLUSIVE | Insufficient/conflicting evidence, timeout, interrupted attempt or unknown health |
| BLOCKED | Preconditions/authorization/policy prevented execution |
| ERROR | Runner/module/evaluator failed; valid partial evidence retained |

Recovery outcome is independently NOT_NEEDED, PENDING, VERIFIED_CLEAN, RESTORED_VERIFIED, or RECOVERY_FAILED. Cleanup/recovery status may outlive a terminal attempt. DEMONSTRATED requires a per-attempt challenge/marker and a negative control where meaningful; stale output, replayed marker, status 200, a generic banner or the framework reporting success is insufficient. If proof contradicts the expected condition, preserve both records and require review.

A lifecycle uses DRAFT, AWAITING_APPROVAL, APPROVED, QUEUED, PREFLIGHT, RUNNING, SESSION_ACTIVE, STOPPING, RECOVERING, COMPLETED, FAILED, CANCELLED, TIMED_OUT, DENIED, EXPIRED, and BLOCKED. SESSION_ACTIVE is permitted only for an approved session-producing plan. The parent attempt cannot be COMPLETED while its session/listener remains active. Terminal lifecycle and proof/recovery outcomes are separate dimensions. Every transition is persisted/idempotent. Cancellation before start has no proof attempt; after activity it retains INCONCLUSIVE or already established DEMONSTRATED evidence as appropriate. A retry cannot be hidden within one attempt.

Link demonstrated effects to the canonical issue as validation evidence, recording the lab build and exact behavior. It does not automatically prove all production instances or variants are exploitable. Failed proof attempts do not close findings or downgrade severity. Priority may increase through a reviewed evidence event with clear rationale; severity/CVSS changes require their normal review rules. A repaired fixture may be retested with a fresh approved plan; failed repeat exploitation alone cannot establish RESOLVED_VERIFIED without adequate desired-state evidence.

### 21.8 UI and reports

Add an Exploitability tab with prerequisites, compatible admitted modules, unavailable research references, confidence/freshness, expected effect and plan action. Add a Lab Proof area with engagement details, admin queue, execution/health states, live output, stop action, proof evidence and recovery status. Section 22 adds the session workspace and advanced terminal. Hide/deny controls for ineligible targets. Never offer a generic framework console, arbitrary payload field, automatic “exploit all” button, or module options beyond typed admitted inputs.

Reports separate candidate applicability, supported detected conditions, prerequisite assessments, attempts and demonstrated impact. Include unsuccessful/inconclusive attempts, proof/runtime limitations, fixture identity, module/hash, operator/approval, negative controls, effect boundary, recovery incidents and final readiness. Export redacted structured proof/recovery records with existing assignment rules; notification details never leak unassigned lab targets. Do not describe an assessment as exploitation success or a failed proof as a clean scan.

### 21.9 Requirements and acceptance gates

All requirements below are Must for enabling the corresponding capability. Offline assessment and one-shot proofs may ship before sessions; each later mode has its own explicit release gate.

| ID | Requirement |
|---|---|
| LAB-01 | Register exact recoverable isolated fixture identity; private IP/public-scan approval cannot establish eligibility |
| LAB-02 | Verify a restore rehearsal, fresh baseline and snapshot, blast radius, and target lock before proof |
| ASM-01 | Evaluate prerequisite evidence with satisfied/missing/contradicted/unknown/stale states and reasoned eligibility |
| ASM-02 | Keep offline dry run free of target traffic; separately approve every active check |
| MOD-01 | Admit immutable exact module/action revisions, dependencies, typed options, fixed effects and evidence contracts |
| MOD-02 | Review check behavior independently; no implicit harmless-check assumption or arbitrary framework fallback |
| POC-01 | Require proof-specific attestation/one-time fresh plan approval; scan approval never suffices |
| POC-02 | Execute one selected module/surface/attempt; no unattended schedules, retries, chaining or catalog-wide launches |
| POC-03 | Use isolated disposable worker and enforced exact egress; reject unprovable Windows/network boundaries |
| POC-04 | Enforce short runtime/request budgets and health-based stop; stop full worker/framework process activity |
| POC-05 | Prove fixed benign effect with nonce-correlated evidence and meaningful controls; raw success is insufficient |
| POC-06 | Prohibit credentials, unapproved shells/payloads, persistence, lateral movement, real-data harvesting, DoS and evasion; enforce section 22 grants for admitted interaction |
| REC-01 | Track worker termination, target cleanup/restoration and health independently; block unsafe subsequent work |
| REC-02 | Preserve recovery incidents through timeout/restart and require verified administrative recovery |
| RES-01 | Keep prerequisite/check/proof/recovery outcomes separate; failed attempt cannot prove safety or remediation |
| RES-02 | Audit/export exact plan, hashes, effects, evidence, operator, approval and recovery with assignment protection |

Required test scenarios:

| Scenario | Acceptance result |
|---|---|
| Owned public target or private production host requests proof | BLOCKED before launch; normal scan policy unchanged |
| Scan approval reused for active check/proof; stale or replayed approval | No unauthorized action starts |
| Unknown build, stale evidence, snapshot mismatch or disabled module | Hold/block; no automatic downgrade/override |
| Framework check named Safe/Appears/Unknown without adequate telemetry | Preserved native outcome; conservative claim; no global safety badge |
| Generic RPC/console/module options, dependency change, arbitrary payload | Backend rejects; plan hash and manifest enforcement pass |
| Proof worker tries another target/internet/control-plane destination | Traffic blocked at the network boundary; attempt stopped and audited |
| Seeded vulnerable fixture executes fixed proof; patched fixture tested | Correct nonce-bound demonstration on vulnerable fixture; no false demonstration on patched/negative fixture |
| Replayed output/marker or module exit 0 without proof evidence | INCONCLUSIVE or ATTEMPTED_NOT_DEMONSTRATED, never DEMONSTRATED |
| Health loss, cancel, timeout, stop or worker crash | Worker stopped; evidence preserved; fixture remains locked until verified recovery |
| Worker destroyed while target retains marker/state change | Target recovery remains outstanding; no clean-state assumption |
| Snapshot restore fails or would affect another workload | Recovery incident/block; no broad restoration fallback |
| Successful proof plus failed recovery | Both facts remain visible; subsequent activity blocked |
| Failed proof followed by a closure request | No automatic remediation/absence inference |
| Changed module/effect/options or another attempt | Fresh attestation and approval required |
| Export/notification viewed by unassigned user | Denied; no lab evidence/control access leak |

Before enabling actual execution, demonstrate these scenarios on the supported Docker Desktop topology and record one real reviewed fixed-effect proof plus its patched negative control and successful target recovery. Unavailable framework support or failed lab isolation keeps execution disabled while offline assessment remains useful. Interactive sessions/terminal additionally require section 22 acceptance. Public-target exploitation, credential testing and effects outside the approved lab modes remain excluded.

## 22. Interactive execution and lab sessions

### 22.1 Modes and scope

The requested interaction is delivered in three stages. Live execution controls work with existing approved attempts. Guided sessions add predefined validation actions to an admitted session-producing proof. The optional administrator terminal permits free-form input to that one target session after a separate release and authorization gate. This section explicitly replaces v2.1's blanket session prohibition; baseline reconnaissance, target eligibility, and the remaining exclusions continue to apply.

| Mode | Operator interaction | Permission boundary |
|---|---|---|
| Execution workspace | Watch status/output, stop attempt, annotate and capture evidence | Existing approved attempt and assigned target |
| Guided session | Select a predefined admitted action; inspect its output and attach evidence | Verified session, named operator, active action grant and controller lease |
| Advanced terminal | Enter target-session input; inspect streaming output | Administrator only, explicit terminal grant, verified isolated fixture and terminal release gate |

The terminal connects to a target session; it is not a framework console, worker/host terminal or generic RPC endpoint. Do not enable autonomous agents to operate sessions or generate/submit terminal commands. AI coding assistance develops the application; an approved human operator controls lab interaction.

Do not enable credential testing, credential harvesting, persistence, lateral movement, real-data collection, destructive actions, denial of service or evasion through any mode. Guided actions can technically restrict accepted operations. A free-form terminal cannot reliably guarantee the meaning/effects of every command through a blacklist; its protection depends on a trusted authorized administrator, a disposable synthetic-data fixture, enforced network containment, limited lifetime, transcript accountability and recovery. Record that difference rather than claiming terminal input is universally safe or read-only.

### 22.2 Adapter and service boundaries

The Metasploit adapter translates approved Trash Scan domain operations into framework calls and translates results back. The application owns scope, assignment, approvals, module admission, option schemas, intelligence matching, job/session ownership, policy and report semantics. The framework supplies admitted module and session mechanics. A framework job ID or session alone is not evidence that the finding's claimed impact occurred.

| Backend operation | Adapter responsibility | Application responsibility |
|---|---|---|
| Catalog/details | Read admitted module metadata/options | Filter approved revisions; identify research-only references |
| Check | Invoke the reviewed check operation where supported | Authorize plan/impact; evaluate evidence conservatively |
| Execute/status/stop | Start admitted action; correlate and poll/stop its job | Consume approval once; enforce limits and stop conditions |
| Session discovery | Read instance-local session metadata | Verify attempt/fixture association; quarantine ambiguous sessions |
| Session output | Retrieve supported output using backend-owned cursor | Sequence, redact, bound, persist and authorize output |
| Guided action | Translate a typed admitted action using fixed implementation | Validate grant/lease/schema; record request and result |
| Terminal input | Transport bounded input frames to the admitted target-session type | Enforce administrator terminal grant and frame ordering |
| Session termination | Request session termination and stop associated listener/job | Confirm stop, revoke grants, reconcile and recover target |

Use an explicit typed interface such as `describe_module`, `check_plan`, `start_attempt`, `get_job_state`, `stop_job`, `discover_sessions`, `read_session_output`, `execute_guided_action`, `write_terminal_frame`, and `stop_session`. These are application interface names, not claims about exact RPC method names. Validate native methods/result schemas against the pinned framework version; advertise a capability matrix. Missing check, session type, output or terminal support displays NOT_SUPPORTED; there is no fallback to arbitrary console commands.

Keep a fake adapter with deterministic jobs, session events, output chunks, errors and lost acknowledgements for development. Separate backend credentials for RPC/control infrastructure from product users; never send credentials or raw framework identifiers to the browser as authorization capabilities. The framework's privileged RPC access does not implement Trash Scan's user roles. Pin the framework instance/image and module/dependency revisions, with maintenance and re-review on changes.

### 22.3 Session-aware approval and listener contract

A session-producing proof plan adds an admitted session transport/type, allowed internal listener interface/address/port if needed, allowed target-to-worker route, expected fixture association evidence, named operator, guided action IDs/versions and budgets, session lifetime/idle policy, transcript bounds, disconnect behavior and recovery contract. The approved typed transport configuration must not expose a payload generator or arbitrary options.

Callbacks may reach only the declared listener inside the isolated lab. Do not bind listeners broadly to public/host interfaces, enable port forwarding to other targets, add pivot routes, or contact external callbacks. Validate both directions of the network boundary on the actual Docker Desktop topology. If NAT obscures source identity, require a stronger reviewed fixture association mechanism; do not guess the target from its apparent source IP.

An existing one-shot approval cannot become a session plan. Guided actions named in the approved session grant may be invoked repeatedly within their declared action count/time/byte limits without another attestation for each click. New action types, broader targets/effects, session transport changes, terminal access or extended lifetime require a fresh approved grant. Grant extensions may not reset the original absolute session lifetime; terminate/recover and create a fresh attempt for a longer/new session.

Terminal access requires a separate administrator request/attestation and approval referencing the exact verified session, lab boundary and allowed time. The initial release uses a maximum 10-minute absolute session lifetime from the backend's first observation, a 2-minute idle limit, a 30-second controlling-browser disconnect grace, a 15-second controller lease with 5-second heartbeats, and a 20-minute overall session-plan lifecycle. Establishment remains capped at 120 seconds. A later terminal grant does not restart any clock. Each guided action has a reviewed limit, initially at most 30 seconds and 16 KiB result data; total guided invocations initially at most 20 per session. Lower manifest limits take precedence.

These are proposed product defaults to verify in the lab. Session-bearing attempts consume the global one-active-proof limit and keep the fixture lock through termination and verified recovery. At overall deadline, stop/isolate, retain incomplete recovery and keep the lock; do not invent a clean state to satisfy a deadline. Sessions cannot survive administrative revocation, target-assignment loss, emergency stop, failed health monitoring or an invalidated lab boundary.

### 22.4 Identity, lifecycle and controller ownership

Model a product Session with its own opaque ID, attempt/plan ID, fixture/target, framework instance startup epoch, native session ID/UUID, admitted transport/type, observed connection details, creation/expiry, owner and state. Native IDs may be reused after a framework restart; never use a numeric native session ID as a durable authorization identity. Combine attempt/job correlation, transport identity and reviewed fixture proof; no client-supplied target or framework metadata alone establishes association.

Session states: PENDING, ESTABLISHED_UNVERIFIED, READY, CONTROLLED, STOPPING, CLOSED, LOST, QUARANTINED. Unverified or ambiguous sessions accept no operator input. READY means identity and grants are valid; it does not automatically mean the original vulnerability claim is demonstrated. Any unexpected second session/target/transport is quarantined and triggers stop/review. The system must not silently adopt unrelated framework sessions.

Controller leases enforce one writer across tabs/browsers/operators. Each action/frame carries an opaque request ID, lease fencing token and expected sequence. Validate actor, target assignment, grant, mode, expiry, live lease and health immediately before dispatch. Observers may read permitted output but cannot write. Administrator takeover is explicit/audited: revoke the old lease, prevent queued dispatch, handle any in-flight unknown effect conservatively, then issue a new lease. Do not replay an in-flight operation during transfer.

On disconnect, stop accepting input immediately; permit reconnection within the declared grace only after authentication and fresh lease validation. Reconnection resumes output from a cursor; it never reruns a module/action or extends lifetime. At grace/idle expiry, terminate the session/listener and enter recovery. On backend/framework restart, reconcile attempt, transport, sessions and fixture locks. Orphaned/uncertain sessions are stopped/quarantined and require recovery; missing process state is not evidence of a clean target.

### 22.5 Guided interaction and terminal behavior

Initial guided actions are limited to validated capabilities: inspect current execution identity, retrieve basic OS/architecture context, read/verify a specifically seeded non-sensitive fixture marker, capture a reviewed proof observation, and terminate the session. Fixed marker creation/cleanup may be admitted with its explicit reversible-effect contract. No arbitrary filesystem browser, uploads/downloads, bulk discovery, privilege escalation, route/pivot management or credential actions. Session output is evidence for the precise operation only; observing an identity does not prove additional access or privilege escalation.

Each action definition includes versioned ID, compatible session type, typed parameter schema, fixed implementation, required grant, preconditions, expected output/effect, request/time/byte bounds, evidence evaluator, and any cleanup. Do not implement guided input by substituting untrusted strings into a shell command or by allowing arbitrary framework session commands behind a button. If a fixed implementation requires target command transport, only the admitted template and validated constrained inputs may be sent.

Interaction records use REQUESTED, AUTHORIZED, DISPATCHED, COMPLETED, OUTCOME_UNKNOWN, REJECTED, CANCELLED. A timeout/disconnect after dispatch may leave the remote outcome unknown; never automatically resend. Persist the intended action/request before dispatch. Idempotency prevents duplicate browser requests from generating duplicate remote operations, but does not claim exactly-once execution across an uncertain RPC failure. Halt new modifying input pending reconciliation/review when its effect is uncertain.

Advanced terminal input is separately feature-gated and administrator-only. Use ordered bounded frames with request IDs and backpressure; initially cap input frames at 4 KiB and paste at 4 KiB pending a deliberate operator acknowledgement. Large output is bounded, truncated visibly and linked to the transcript. A command blacklist is not the authorization boundary. Record input provenance and output timing, but do not fabricate command completion or exit status when the transport cannot supply it. Unsupported PTY, resizing, binary streams or interactive programs display the actual capability limit; a command-output panel must not masquerade as a full terminal.

The terminal cannot start new modules, change framework settings or reconnect to a different target. It acts only through the admitted target-session channel. Commands remain subject to the engagement exclusions and trusted-operator policy; containment/recovery must be demonstrated before terminal enablement. Terminating a terminal view is distinct from terminating the target session; the UI exposes both with literal labels and enforces disconnect expiry.

### 22.6 Streaming, transcripts and evidence

The browser opens an authenticated WebSocket through StreamGateway. Check secure origin, authentication, assigned target and view/control permission at connection and every input message, and revoke existing subscriptions when those rights change. Use secure transport beyond localhost, bounded message sizes, queue/backpressure and rate limits. Browser tokens must not appear in URLs or transcripts. The browser never connects directly to framework RPC/listeners.

Stream normalized status, output and evidence events with stream/session/attempt IDs, monotonic sequence, server UTC timestamp, type and sanitized payload. A backend-owned collector reads native output once and fans out events so multiple observers cannot consume each other's framework buffers. Reconnect uses the last acknowledged output cursor; if retained output is unavailable, emit a visible gap event. Status/recovery state is durable database truth; output events cannot overwrite it.

Store a bounded redacted transcript linked to the attempt/session. Proposed limit is 1 MiB text per session plus bounded structured evidence; if input/evidence audit cannot be recorded, stop new interaction. Output overflow marks gaps/truncation, applies backpressure and follows the manifest's safe stop policy. Remove active terminal escape/control sequences from archived/UI output as needed, escape HTML and prevent output from executing code or opening unintended links. A terminal renderer is display infrastructure, not an execution boundary.

Audit grant/lease/transfer, every accepted/rejected interaction, input-frame dispatch, stop reasons, evidence capture and recovery. Preserve hashes and redacted summaries without storing RPC credentials, cookies, tokens or secrets in the permanent chain. Synthetic fixture data must still be handled as untrusted. Evidence capture records the exact event range, actor, evaluator, effect claim and limitations. A session opened, a command returned output, and a declared proof succeeded are separate evidence events.

Add SessionGrant, ControllerLease, GuidedActionRevision, InteractionRecord, TerminalFrameReceipt, StreamEvent/Transcript and SessionEvidence entities. New records reference existing target/attempt/approval/recovery identities; no automatic upgrading of old one-shot approvals or historical proof outcomes. All views/exports/notifications apply assignment policy.

### 22.7 User experience and API contract

Execution workspace shows finding/module, prerequisites/options, administrator approval, active stage, live output, proof/health/recovery state, stop control and evidence capture. Session workspace adds verified fixture identity, mode/capabilities, named controller, lease/expiry timers, guided action panel, output/transcript, end-session control and recovery status. Show a clear read-only observer state and pending/denied control requests. Keep security language literal and keyboard accessible.

Proposed application API shape below is a design contract to adapt to existing routing conventions; identifiers are product IDs, never caller-chosen framework IDs. All mutations need current authorization and idempotency/lease checks appropriate to the operation.

| API surface | Purpose |
|---|---|
| Approved module catalog/details | Read admitted revisions, compatibility and capability status |
| Assessments and proof-plan requests | Evaluate evidence; submit exact plan and approval request |
| Attempts read/stop/output | Inspect durable state, stop activity and subscribe to bounded output |
| Sessions read | List assigned verified session metadata and status |
| Session control acquire/release/transfer | Manage the single controller lease with audited permissions |
| Session guided actions | Submit a typed versioned action under its existing grant |
| Session terminal-grant request/approval | Explicitly authorize administrator terminal mode |
| Session terminal input | Submit ordered bounded frames after terminal grant |
| Session evidence/end | Capture permitted output evidence; terminate and initiate recovery |
| Transcript/report export | Export redacted records with current assignment checks |

Do not add a generic `rpc(method, parameters)` or `execute_command(any target)` API. Raw terminal input belongs only to its specifically granted verified session. Normal controls and application routes do not accept arbitrary target selectors, framework module paths or hidden option overrides.

### 22.8 Requirements and acceptance

| ID | Requirement | Gate |
|---|---|---|
| ADP-01 | Required typed restricted real Metasploit adapter, pinned capability matrix and fake adapter | Framework phases |
| ADP-02 | Backend-only privileged RPC credentials; no generic API/console fallback | Framework phases |
| LIV-01 | Durable sequenced status, bounded live output, stop and evidence capture | Live workspace |
| LIV-02 | Authenticated authorized streaming, redaction, backpressure, cursor resume and visible gaps | Live workspace |
| SES-01 | Bind sessions to exact attempt/fixture/instance epoch; quarantine ambiguous/unexpected sessions | Sessions |
| SES-02 | Approve exact internal listener/transport and verify both network directions | Sessions |
| SES-03 | Enforce named operator/action grant, absolute/idle/disconnect limits and target locks | Sessions |
| SES-04 | Enforce single writer with fenced leases and audited takeover | Guided interaction |
| SES-05 | Use versioned typed guided actions with explicit effects/bounds; no hidden arbitrary commands | Guided interaction |
| SES-06 | Persist interaction intent/receipt/outcome; no automatic resend after uncertain dispatch | Guided interaction |
| SES-07 | Revoke active access promptly on assignment/account/policy/grant changes | Sessions |
| SES-08 | Stop session/listener/job, reconcile restarts and verify target recovery separately | Sessions |
| SES-09 | Retain redacted bounded transcripts and evidence with clear gaps and claim semantics | Sessions |
| TER-01 | Terminal is administrator-only, separately granted and disabled until its release gate | Optional terminal |
| TER-02 | Terminal operates only on one verified target session; ordered bounded input and output | Optional terminal |
| TER-03 | No command-filter safety claim; verified isolated synthetic fixture, trusted operator, time limits and recovery | Optional terminal |
| TER-04 | No local shell interpolation, framework console, raw RPC, arbitrary target or payload generation | Optional terminal |

All listed requirements are Must when that mode is enabled. Terminal may remain disabled without blocking acceptance of guided mode, but its development phase and prerequisites are included in this PRD.

Acceptance must demonstrate unauthorized WebSocket connection/input denied; assignment loss removes live access; native session ID reuse does not cross-bind targets; unexpected callback/session quarantined; public/other-target callback blocked; dual-controller writes prevented; old lease rejected after transfer; request replay produces no second remote operation; uncertain RPC dispatch is not retried; reconnect resumes output without restarting work; expired sessions/listeners terminate; output cannot execute HTML/terminal escape actions; output/audit failure follows bounds; end-session cleans up the listener as well as the session; worker loss does not release an unverified target lock; and denied terminal grants never reach target input. Run a real session on the admitted lab fixture and a patched negative before session release; mocks cannot satisfy that integration gate.

## 23. Detailed development phases for AI-assisted implementation

### 23.1 Phase policy and change map

Original Phases 0–6 describe baseline reconnaissance and enrichment. Verify them first. New phases below are extensions; an existing implementation can satisfy a deliverable only through recorded current evidence. Phase IDs 7–24 are stable. Keep a development ledger distinct from product scan/proof runtime states.

| Major difference from original attachment | Development phases |
|---|---|
| Per-check coverage, evidence and completion-with-gaps | 8 |
| Cross-tool canonical issues and granular comparison | 9 |
| Corrected contextual TLS/DNS/header rules and broader reviewed detections | 10 |
| CVE applicability, offline intelligence and priority policy | 11 |
| Ownership, review, exceptions, closure/retest and JSON export | 12 |
| Exploitability prerequisites and admitted module catalog | 13 |
| New Metasploit Framework backend integration | 14 |
| Mandatory proof-worker isolation and recoverable lab fixtures | 15 |
| Separate approval and actual controlled proof execution | 16 |
| Live execution workspace/streaming | 17 |
| New session domain, grants and ownership | 18 |
| Internal listeners/callbacks and verified session establishment | 19 |
| Guided session operations | 20 |
| Session transcripts, evidence and recovery reporting | 21 |
| Optional administrator target-session terminal | 22 |
| Real integrated release and reviewed capability growth | 23–24 |

Each phase has a code gate and, where required, a distinct real-lab gate. Use NOT_STARTED, IN_PROGRESS, CODE_VERIFIED, LAB_PENDING, ACCEPTED or BLOCKED in the development ledger. A fake-adapter demonstration can earn CODE_VERIFIED, never a required real-lab ACCEPTED. AI agents may build later disabled/fake-backed code after declared code dependencies pass; no real active capability is enabled until all its prerequisite lab gates pass.

Unless a phase explicitly requires ACCEPTED or real-lab acceptance, its dependency list requires the earlier code gate. In particular, Phase 14's metadata/RPC code gate allows Phase 15 lab infrastructure development; a state-changing live check is withheld until Phase 15's lab gate passes. This avoids a circular dependency without relaxing execution readiness.

For every phase, create a small vertical slice, preserve working baseline behavior, add migrations only where needed, run meaningful relevant checks, and record changes/tests/limitations. Avoid full-system rewrites. Dependency order is mandatory for enabled behavior; do not turn unknown platform capability into an assumed success.

### Phase 7 — Baseline verification and repository plan

**Depends on:** Available repository/source and this PRD; original Phases 0–6 are audited here.

**Deliverables:** Map actual accounts/scope/approval/lifecycle/adapters/results/reporting to requirements. Inspect original acceptance/implementation documents. Create `docs/IMPLEMENTATION_LEDGER.md`, a migration inventory and architecture decisions where needed. Record Windows/Docker/lab reachability and raw-packet capability matrix. Identify the default-community policy conflict and unsafe outbound scope paths.

**AI work:** Repository inspection, relevant baseline tests, fake scanner smoke, gap table and concrete change plan. Mark already satisfied requirements with test/file evidence; do not rebuild them.

**Real-lab gate:** Validate the original missing network/cancellation spike on the user's actual lab. Code can progress with unsupported flags disabled while this remains LAB_PENDING.

**Exit/handoff:** Current architecture and critical gaps are documented; baseline checks pass or failures are explicitly tracked. No claim that the attachment's delivered annotations constitute verification.

### Phase 8 — Coverage ledger and evidence foundation

**Depends on:** Phase 7 code gate.

**Deliverables:** AssessmentUnit/immutable Observation schema, bounded redaction/evidence references, adapter outcome contracts, COMPLETED_WITH_GAPS and NOT_ASSESSED presentation. Add per-check telemetry or conservative INCONCLUSIVE outcomes where completion is unobservable.

**AI work:** Migrations and fixture-backed parser/domain/API slice, then target/scan coverage detail. Test exit-zero skipped checks, truncated output and budget exhaustion against historical findings.

**Exit/handoff:** Known incomplete units cannot clear findings; evidence minimization works; rollback/backup implications documented. Record which adapters still lack per-check conclusive negatives.

### Phase 9 — Canonical issues, comparison and legacy migration

**Depends on:** Phase 8.

**Deliverables:** Issue/Occurrence identities, explicit equivalent-detector mappings, per-surface baselines, legacy ID aliases and lossless backfill. Preserve virtual hosts and target assignments.

**AI work:** Migrate a sanitized dataset and implement issue detail/history APIs before UI grouping. Exercise equivalent outputs, distinct hosts sharing an IP, changed rule semantics and intervening failed scans.

**Exit/handoff:** No historical evidence lost, unsafe merge or fabricated legacy coverage. Compatible negative results produce NOT_OBSERVED; failures produce NOT_ASSESSED. Retain a reversible migration/recovery record.

### Phase 10 — Contextual accuracy and detection coverage

**Depends on:** Phases 8–9.

**Deliverables:** Correct TLS/DNS/header/soft-404 interpretation, reviewed rule-family manifests, trust/domain-role configuration and remediation guidance. Disable credential/community probes under the preserved boundary. Add serious-condition detections only after behavioral review.

**AI work:** Implement one rule family per work unit with positive, negative and ambiguity fixtures; then expose its capability/coverage in UI. Keep explicit protocol-support probes unavailable until validated.

**Real-lab gate:** Demonstrate admitted changed probes and rate/boundary behavior on owned fixtures; scope/traffic changes require their normal approval.

**Exit/handoff:** Mandatory negative-control corpus passes; unknown DNS/TLS input is not misclassified. Record tested families and unavailable capabilities, not a broad vulnerability-coverage claim.

### Phase 11 — CVE intelligence and priority

**Depends on:** Phases 9–10.

**Deliverables:** CandidateAssociation, applicability-rule versions, local knowledge snapshots, vendor references, KEV/EPSS/CVSS fields and deterministic explainable priority. Offline mode and stale/unknown values remain functional.

**AI work:** Use sanitized snapshot fixtures and dated records; implement matching and enrichment events without sending target data. Verify range boundaries/configuration logic, backport ambiguity and candidate-versus-supported counts.

**Exit/handoff:** Feed changes cannot fabricate observations or alter frozen reports. Missing intelligence is not zero risk. Record supported schema/provider versions and refresh configuration.

### Phase 12 — Review, focused retest and export

**Depends on:** Phases 9–11.

**Deliverables:** Owner/due-date workflow, validation/disposition, risk exceptions/expiry, verified closure/reopening, focused approved retest, and redacted JSON alongside PDF/CSV. Preserve all assignment controls.

**AI work:** Backend review transitions and audit first; UI/forms/reports second. Test permissions, expired exceptions, incompatible/failed retest and recurrence after verified closure.

**Exit/handoff:** Negative scan results alone cannot verify remediation; exports/counts preserve candidates, exclusions and coverage. This is the result-quality release gate before integrating real exploitation.

### Phase 13 — Module registry and exploitability assessment

**Depends on:** Phases 10–12.

**Deliverables:** ModuleRevision/admission schema, exact hashes/dependencies, research-only versus executable records, ExploitabilityAssessment prerequisite/freshness logic, dry run and operator planning view.

**AI work:** Fake catalog/action manifests, applicability fixtures and typed option validation. No target-contact activity is needed for the initial assessment slice. Design active-check plans using the existing approval model.

**Human review:** Admit actual module/check revisions and their effect/recovery contracts; a catalog import is not admission.

**Exit/handoff:** Unknown/stale/incompatible prerequisites cannot become eligibility or auto-execution. Record the first proposed lab module and missing conditions.

### Phase 14 — Restricted real Metasploit adapter

**Depends on:** Phases 7 and 13; active checks require relevant lab/approval gates.

**Deliverables:** Pinned framework sidecar/instance, backend protected RPC integration, typed capability matrix, metadata/check/job operations, fake adapter and sanitized native response fixtures. Framework-backed phases require this adapter; generic RPC/console passthrough is absent.

**AI work:** Contract tests for unsupported methods/types, native errors, job ID correlation, lost acknowledgements and duplicate task delivery. Develop on fakes before a local instance integration; no local-shell fallback.

**Real-lab gate:** Verify exact metadata/check/job API behavior against the selected Framework version. Any target-contact check needs its own reviewed plan/approval; state-changing checks require Phase 15 isolation/recovery first.

**Exit/handoff:** Privileged RPC secrets stay backend-only; capability limitations are documented. Check outcomes are interpreted conservatively. Record exact framework/image/module revisions and tested methods.

### Phase 15 — Lab isolation, snapshots, health and recovery

**Depends on:** Phases 7 and 14.

**Deliverables:** LabEnvironment/FixtureBaseline/RecoveryRecord, separate disposable proof worker, exact egress policy, fixture locks, baseline health, snapshot binding and tested restore workflow. No host socket or production volume is available to modules.

**AI work:** Provider interfaces and fake lab controller, readiness policies, lock/recovery APIs, failure scenarios and configuration documentation. Real provider integration follows the actual user's hypervisor choice; do not invent support.

**Real-lab gate:** On Windows/Docker, demonstrate target-only traffic, blocked control-plane/internet/other-target traffic, cancellation and a successful fixture restore rehearsal with recorded blast radius.

**Exit/handoff:** The admitted fixture is recoverable and isolation proven. A missing snapshot/provider/network proof leaves actual execution BLOCKED, while code may remain CODE_VERIFIED.

### Phase 16 — Approved one-shot proof execution

**Depends on:** Phases 12–15; Phase 15 real-lab acceptance for execution.

**Deliverables:** Immutable ProofPlan, proof attestation/approval, ProofAttempt orchestration, fixed evaluator, short budgets, health stops and separate recovery outcomes. One selected module/target/attempt; no retry or scheduling.

**AI work:** Transactional one-time approval/dispatch, worker lifecycle and fake success/failure/crash scenarios, followed by the smallest genuine admitted fixed-effect proof.

**Real-lab gate:** Demonstrate the proof on a seeded vulnerable fixture, fail to demonstrate on its patched/negative fixture, reject replayed evidence, and restore/verify the target. Stopping the worker is not recovery evidence.

**Exit/handoff:** Module started, proof demonstrated and recovery verified remain distinct. No actual-session capability is enabled yet. Record measured traffic/time and artifacts.

### Phase 17 — Live execution workspace

**Depends on:** Phases 8, 12, 14 and 16 code gates; real execution follows Phase 16 acceptance.

**Deliverables:** Execution UI, StreamGateway, durable status/output events, live stop, annotations/evidence capture, bounded replay/gaps and redaction. Use fake streams to build UI without target traffic.

**AI work:** API/stream contract first, then progressive UI. Exercise unauthorized observer, assignment revocation, disconnect/reconnect, out-of-order/gapped events, malicious output and backpressure.

**Exit/handoff:** Reconnect cannot rerun work; UI state matches database lifecycle. Stop requests acknowledge promptly and show confirmed/failed termination accurately. Record streaming/retention bounds.

### Phase 18 — Session domain and broker on fakes

**Depends on:** Phases 13–14 and 17.

**Deliverables:** Session/SessionGrant/ControllerLease migrations, verified/unverified/quarantined states, admission schemas for session transport and callbacks, typed interaction records and broker API. Sessions remain disabled against real targets.

**AI work:** Fake session discovery/output/termination, instance-epoch identity, grant/expiry policies, fenced single-writer leases and idempotent intent records. Test native ID reuse and ambiguous cross-target association.

**Exit/handoff:** Unverified sessions accept no input; observers cannot control; takeover invalidates old writers. Clearly mark simulated session data and absent real listener support.

### Phase 19 — Internal listener and verified session establishment

**Depends on:** Phases 14–18, with Phase 15 lab acceptance.

**Deliverables:** One admitted session-producing module/transport, session-aware proof plan, exact internal listener/callback boundary, attempt/fixture association, session-aware parent lifecycle and session termination.

**AI work:** Admission/plan schema, explicit route reservation, native-session polling and binding, timeout/error handling and unexpected-session quarantine. Do not expose input before association passes.

**Real-lab gate:** Demonstrate both traffic directions on the actual topology, including NAT behavior, unexpected callback rejection, no public listener, successful fixture association and cleanup. Compare vulnerable and patched/negative fixtures.

**Exit/handoff:** The exact session can reach READY through recorded evidence, and stop removes both listener and session. Session establishment alone does not prove every claimed impact. Record supported session type/transport.

### Phase 20 — Guided session actions and ownership

**Depends on:** Phases 18–19, including real session acceptance for enablement.

**Deliverables:** Initial action registry, typed inputs, named operator/action grants, lease heartbeat/takeover, session workspace/action panel, guarded dispatch and unknown-outcome handling.

**AI work:** Add one action at a time: execution identity, basic environment context, seeded marker verification, evidence capture and termination. Use fakes for API/UI race conditions, then run admitted actions on the lab session.

**Exit/handoff:** Requests outside the grant, stale leases and duplicate IDs are rejected; uncertain RPC dispatch is not repeated. Demonstrate two competing controllers and assignment loss. Record action versions/effects/limits.

### Phase 21 — Session transcripts, evidence and recovery

**Depends on:** Phases 15, 17 and 20.

**Deliverables:** Bounded redacted transcript/stream cursors, session evidence/ranges, idle/absolute/disconnect termination, restart reconciliation, session/listener/worker stop and target recovery, updated PDF/CSV/JSON.

**AI work:** Transcript/evidence domain and export first; UI timeline next. Test replayed marker, missing output, malicious control sequences, stop/health failure, storage exhaustion and restart with a lingering session.

**Real-lab gate:** Verify disconnect/expiry/stop termination and restore after session use, including a deliberately failed recovery scenario. No fixture lock is released before readiness verification.

**Exit/handoff:** Guided interaction release is accepted independently of optional terminal. Reports distinguish demonstrated effect, session state, transcript gaps and recovery incident; privacy/access tests pass.

### Phase 22 — Optional administrator target-session terminal

**Depends on:** Phases 15 and 19–21 accepted; explicit terminal admission/release gate.

**Deliverables:** Separate terminal feature flag/grant/attestation, administrator-only input broker, ordered frame receipts, output renderer/capability disclosure, paste/buffer limits, operator accountability and termination/recovery UI. No framework console or host terminal.

**AI work:** Build fake terminal UI and input receipts first, verify permissions and frame deduplication without real commands. Integrate only the admitted session transport's supported input/output path; missing PTY/resize support is disclosed.

**Real-lab gate:** Test isolation, expiry/revocation, single controller, uncertain dispatch, reconnect without input replay and final recovery on a disposable synthetic-data fixture. Validate the operator policy; do not claim a command blacklist enforces safe semantics.

**Exit/handoff:** Terminal stays disabled until the gate passes and an administrator grants a specific session. Guided mode remains usable if terminal is deferred. Record exact supported interaction capabilities and known limits.

### Phase 23 — Integrated release acceptance

**Depends on:** Phases 7–21; include Phase 22 only if terminal is enabled for this release.

**Deliverables:** Updated installation/configuration/operator docs, implementation/acceptance ledger, migrations/backups, image/module manifests, default feature flags and end-to-end reports. Publish mode-specific capability support; no mode is enabled by a mock result.

**AI work:** Run the relevant integrated checks, verify fake/demo data separation, documentation and restore/migration fixtures. Resolve regressions within affected phases rather than generating a replacement app.

**Real-lab gate:** Complete authorized scan → candidate/assessment → approved proof → optional verified session → guided actions → evidence → stop/recovery → remediation/retest on the supported Windows lab. Verify patched negatives and all enabled mode boundaries.

**Exit/handoff:** Every Must requirement for enabled modes has evidence. Disabled optional modes are explicitly documented; remaining failures have owner and impact. No claim of broad vulnerability absence or universal exploitability.

### Phase 24 — Reviewed module and capability growth

**Depends on:** Phase 23 and the applicable prior capability gates.

**Deliverables:** Incremental new module/action/session-type revisions with manifest, prerequisites, admitted effects, fixtures, negative controls, measured limits and recovery evidence. Repeat compatibility and report interpretation checks for each.

**AI work:** One admitted capability per work unit; reuse existing interfaces and rerun affected acceptance scenarios. Propose research references separately from executable admissions. Never enable an entire framework catalog by default.

**Real-lab gate:** Revalidate actual target build, routing/session support and cleanup/restore for each new action. A dependency/module update may require re-review of earlier admissions.

**Exit/handoff:** Each new capability has its own acceptance record and exact pinned revision. Public-target exploitation, credential testing, persistence, lateral movement and destructive testing remain outside this revision.

## 24. AI-agent development and handoff contract

### 24.1 Required repository records

Maintain `docs/IMPLEMENTATION_LEDGER.md` with requirement ID, original versus extension status, implementation references, phase, verification evidence, remaining limitations and enabled modes. Maintain `docs/PHASE_HANDOFF.md` with the current phase/work unit, completed changes/migrations, checks/results, lab pending items, next eligible work unit and feature state. Preserve an existing equivalent repository format if it already provides these fields; do not create duplicate sources of truth.

Record platform/network/module decisions in architecture decision records and mode-specific acceptance evidence in the existing acceptance documentation or `docs/ACCEPTANCE_V2.md`. These paths are requirements for the implementation repository, not files claimed to exist or created by this PRD revision. Raw credentials, sensitive transcripts or real secrets do not belong in handoff records or AI prompts.

Split each phase into small work units in this order where applicable: schema/migration and typed contracts; domain policies/state transitions; adapters/fakes; API and authorization; UI; failure-path/integration verification; documentation/handoff. Keep the app runnable after each unit. Do not build later UI around unsupported backend guarantees.

### 24.2 Reusable task prompt for the coding agent

```text
Implement Phase <number>, work unit <name>, from Trash Scan PRD v2.2.

Read the current implementation ledger, phase handoff, repository guidance,
the selected phase, and its referenced requirements before editing.
Verify prerequisites against current code/tests; preserve working baseline features.
Implement the smallest runnable vertical slice needed for this work unit.
Use fake adapters and sanitized fixtures while real lab gates remain pending.
Add a new migration for schema changes; preserve data, approvals and audit history.
Keep proof/session/terminal features disabled until their actual release gates pass.
Run meaningful checks for the changed behavior and resolve applicable failures.
Update the requirement ledger and phase handoff with evidence and limitations.
Report what changed, how it was verified, what remains uncertain, and the next unit.

Do not add unreviewed modules, arbitrary RPC/console interfaces, automatic retries
of uncertain remote operations, or assumed Windows/network capabilities.
This development task does not itself authorize real scans or proof execution.
```

Replace placeholders with an actual numbered phase and bounded unit before giving this prompt to the AI. For the initial turn, request Phase 7 repository audit; use its evidence to determine whether the next work is baseline repair or Phase 8. Later turns may say “continue the next eligible work unit recorded in the handoff,” provided the agent first rereads the current records. Do not restart original phases already verified.

### 24.3 Definition of phase completion

Completion requires implementation references, relevant meaningful passing checks, preserved data/authorization invariants, documented enabled/disabled modes, migration/recovery implications, and acceptance evidence for any required real-lab behavior. Separate CODE_VERIFIED from ACCEPTED when hands-on tests are pending. The agent must not invent observations, label fake results as live, or infer a successful lab gate from compilation/unit tests.

New target-contact behavior follows the product's explicit approval mechanism and the lab owner's authorization. Module admission, network/capability changes and terminal enablement receive their specified review. Routine reversible code work proceeds within the assigned development scope; the agent should not turn every implementation choice into an approval request.

Before each handoff, document outstanding uncertainty plainly. If a platform gate is blocked, continue independent disabled/fake-backed work only where the phase dependency policy permits it, and identify the exact hands-on test/configuration needed to resolve the gate. Avoid a blanket claim that the entire product is complete while enabled-mode Must requirements are missing.

---

**Implementation boundary:** This PRD specifies the product, including its explicitly authorized lab proof and interaction extension. It does not authorize operating against any particular network. The team must own or have authorization for every tested boundary and declared effect. Trash Scan enforces those limits while reporting the limits of evidence, session capability and recovery status.
