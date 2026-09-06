# Trash Scan — Product Requirements Document

**Status:** Draft for implementation  
**Version:** 1.0  
**Date:** 2026-09-06  
**Audience:** Student development and security team; AI coding agents  
**Initial deployment:** Docker Desktop on Windows  

> **Product promise:** Trash Scan helps a student security team inventory and assess an authorized virtual business network while making scope, permission, scan history, and changes visible at every step.

> **Safety boundary:** Trash Scan performs passive discovery and authorized active reconnaissance. It does not exploit vulnerabilities, test credentials, brute-force names or services, create denial of service, spoof sources, or provide evasion controls.

## 1. Executive summary

Trash Scan is a responsive, self-hosted reconnaissance dashboard for a single team of students operating a virtualized network that simulates a business environment. It centralizes target scoping, passive discovery, active-scan approval, scanner execution, findings, historical comparison, scheduling, reporting, and a tamper-evident audit trail.

Private IPv4 ranges are the default permitted scope. An administrator may manually add a specific public target owned by the team after completing a checkbox and typed authorization attestation. Scanners may immediately perform passive discovery on targets assigned to them. Every active execution—including every scheduled active occurrence—requires a fresh administrator approval.

An active approval permits one execution to start within two hours. Once started, the approval does not expire mid-scan; a separate two-hour maximum runtime terminates jobs that run too long. Scheduled attestations remain valid indefinitely while target, profile, ports, limits, and checks remain unchanged, but each active occurrence still waits for administrator approval.

The Python-first application orchestrates pinned versions of Nmap, Subfinder, dnsx, ProjectDiscovery httpx, and a restricted Nuclei template set. It runs through Docker Compose on Docker Desktop and should remain portable to Linux or Kali later.

## 2. Problem statement

The team needs a consistent way to determine:

- What assets exist in the authorized lab.
- Which ports and services they expose.
- Which safe indicators of vulnerability or misconfiguration are present.
- What changed since a previous comparable scan.

Running individual tools manually makes authorization, output formats, assignments, cancellation, scheduling, retention, and comparison inconsistent. Trash Scan solves that coordination problem without becoming an exploitation framework. Authorization and scope are core product behavior, not merely a warning banner.

## 3. Goals

- Provide one responsive dashboard for authorized target discovery, scanning, findings, comparison, scheduling, and export.
- Clearly distinguish passive actions from active actions before execution.
- Require an ethical-use attestation and time-limited administrator approval for every active execution.
- Limit scanners to assigned targets while allowing administrators to manage and scan all targets.
- Run only pinned, administrator-approved free tools and reviewed, non-destructive Nuclei templates.
- Support cancellation, emergency termination, concurrency limits, rate limits, and maximum runtime enforcement.
- Preserve targets and results until administrator deletion, retain temporary operational logs for seven days, and retain the tamper-evident audit trail permanently.
- Support reproducible local deployment using Docker Desktop and Docker Compose.
- Present automated findings as indicators requiring human validation, not proof of exploitability.

## 4. Non-goals

The first release will not include:

- Exploitation, payload delivery, persistence, lateral movement, or post-exploitation activity.
- Credential testing, password spraying, credential stuffing, or authentication brute force.
- DNS wordlist enumeration, directory brute forcing, fuzzing, or unbounded content discovery.
- Denial-of-service, stress testing, resource exhaustion, or intentionally destabilizing checks.
- Source spoofing, decoys, packet fragmentation, monitoring bypass, or evasion-oriented controls.
- Multi-tenant organizations, commercial scanning APIs, cloud-hosted SaaS operation, or mobile applications.
- Automated remediation or automatic claims that a finding has been resolved.
- OWASP Amass, because its first-release use cases overlap with the chosen discovery tools.
- IPv6 scanning, UDP scanning, screenshots, authenticated checks, or user-authored Nuclei templates.

## 5. Users and permissions

### 5.1 Roles

| Capability | Administrator | Scanner |
|---|---|---|
| Manage accounts and global settings | Yes | No |
| Add, assign, archive, or delete targets | Yes | No |
| Add public targets | Yes, with attestation | No |
| View targets and results | All targets | Assigned targets only |
| Run passive discovery | Yes | Yes, on assigned targets |
| Request an active scan | Yes | Yes, on assigned targets |
| Approve active actions | Yes | No |
| Run an approved active scan | Yes | Yes |
| Create and manage schedules | Yes | Request only for assigned targets |
| Cancel a scan | Any scan | Own scan |
| Emergency-stop a scan | Any scan | No |
| Export PDF/CSV | All visible data | Assigned targets only |
| View audit records | Full chain | Events for assigned targets |
| Approve tool/template updates | Yes | No |

### 5.2 Account requirements

- Local accounts only; SSO and LDAP are deferred.
- First-run setup creates the initial administrator.
- Additional accounts are created and disabled by an administrator.
- Store passwords using Argon2id with a unique salt and configurable conservative parameters.
- Use secure, HTTP-only session cookies, CSRF protection, idle expiration, and logout invalidation.
- Enforce role and target assignment on the backend for every protected request. Hidden UI controls are not authorization.

## 6. Target scope and policy

### 6.1 Default private scope

The administrator configures one or more allowed private IPv4 CIDRs representing the virtual lab. The system rejects active execution against an address outside these ranges unless the address is part of a separately approved public target.

Supported target inputs for the MVP:

- Exact IPv4 address.
- IPv4 CIDR range.
- Domain or subdomain name.

### 6.2 Public targets

- Only administrators may add a public IP, narrow public CIDR, domain, or subdomain.
- The administrator must check an ownership/authorization checkbox and type the required attestation.
- Authorization is acknowledgement-based; DNS ownership verification and document upload are not required.
- Discovered related domains, addresses, certificate names, and redirects do not inherit authorization.
- Before active execution, domains must be resolved again and every resulting address must remain within the approved target boundary.
- The saved public-target record must identify its creator, attestation, creation time, exact boundary, and active/inactive state.

### 6.3 Prohibited targets

Trash Scan must reject known government, military, and healthcare domains. Administrators maintain configurable exact-domain, suffix, IP, and CIDR deny rules. Allow rules never override deny rules.

Sector classification from a hostname or IP is imperfect. The interface and documentation must say that this control reduces risk but cannot guarantee identification of every prohibited organization. The private-only default and narrow public-target exception remain the primary safeguards.

### 6.4 Scope enforcement rules

1. Parse and canonicalize the requested host, IP, or CIDR.
2. Confirm that the actor may access the target.
3. Apply exact and range deny rules.
4. Resolve domains immediately before any active stage.
5. Confirm every resolved IP is inside approved scope.
6. Recheck any redirect destination or newly discovered asset independently.
7. Never send active traffic to an unresolved or ambiguous target.
8. Record the scope decision and canonical addresses in the audit chain.

## 7. Reconnaissance capabilities

| Capability | Purpose | Classification | MVP behavior |
|---|---|---|---|
| OSINT | Collect public certificate, registration, and asset references | Passive toward target | Immediate on assigned targets; free sources only |
| DNS resolution | Retrieve records and validate names | Indirect through resolver | No generated wordlists or brute-force mode |
| Passive subdomains | Find names from existing public sources | Passive toward target | Subfinder with free/keyless sources |
| Port scan | Identify reachable TCP ports | Active | Safe or Standard profile; approval required |
| Service/version detection | Estimate network software and versions | Active | Standard profile; approval required |
| SYN scan | Perform TCP SYN-based discovery | Active and observable | Standard profile; approval required |
| OS detection | Estimate the operating system from network responses | Active | Standard profile; show confidence and limitations |
| HTTP inspection | Collect status, title, headers, TLS, and technology indicators | Active | Approval required; bounded redirects and responses |
| Nuclei templates | Detect reviewed exposure and configuration indicators | Active | Allowlisted, non-destructive templates only |

Nmap SYN scanning is sometimes called a “stealth scan,” but Trash Scan will label it **SYN scan** and will not promise invisibility. It still produces observable network traffic. Decoys, spoofing, fragmentation, source manipulation, and timing intended to evade monitoring are prohibited.

### 7.1 Scan profiles

#### Passive

- Public OSINT.
- Passive subdomain discovery.
- DNS record resolution without wordlist generation.
- No administrator approval required.
- Limited to assigned targets and configured scope.

#### Safe active

- Common administrator-defined TCP ports.
- Conservative connection and request rates.
- Basic service metadata.
- HTTP status, title, headers, TLS metadata, and technology detection.
- Reviewed low-impact Nuclei templates.
- Typed attestation and fresh administrator approval required.

#### Standard active

- Broader administrator-defined TCP port set.
- TCP SYN scan.
- Service/version detection.
- OS detection with confidence and environment limitations.
- HTTP inspection.
- The same restricted Nuclei template policy as Safe active.
- Typed attestation and fresh administrator approval required.

## 8. Authorization and attestation

### 8.1 Active execution workflow

1. The requester selects an approved target, profile, permitted options, rate, and immediate or scheduled execution.
2. The requester checks the authorization statement and types the required ethical-use attestation.
3. The backend validates syntax, assignment, scope, deny rules, profile, options, concurrency, and rate limits.
4. Trash Scan creates an approval request and an in-dashboard administrator notification.
5. An administrator reviews the requester, target resolution, profile, ports, rate, schedule, and attestation.
6. The administrator approves or denies the execution and may record a reason.
7. Approval authorizes exactly one execution and expires if the job has not started within two hours.
8. Once the job begins, approval expiration does not stop it. The separate maximum runtime does.

### 8.2 Scheduled scans

- A schedule’s typed attestation remains valid indefinitely for its exact target, profile, ports, checks, rate, and concurrency.
- Every scheduled active occurrence creates a fresh approval request and remains paused until an administrator approves it.
- Passive scheduled occurrences run without approval while still enforcing assignment, scope, concurrency, and rate limits.
- Changing target scope, profile, ports, enabled checks, rate, or concurrency invalidates the stored attestation.
- Approval permits the occurrence to start for two hours.
- A missed occurrence must not silently run at an unexpected later time. Its final state must be visible as expired, denied, cancelled, or explicitly rescheduled.

### 8.3 Runtime

- Default maximum runtime: two hours.
- MVP maximum allowed runtime: two hours.
- The limit is measured from transition to `RUNNING`, not from request or approval time.
- On timeout, terminate the complete process tree, prevent downstream stages, retain valid partial output, and mark the execution `TIMED_OUT`.
- Runtime and approval window are separate values even though both default to two hours.

## 9. Core user journeys

### 9.1 Create and assign a private target

1. Administrator adds a host, CIDR, or internal domain.
2. Trash Scan validates syntax, overlap, deny rules, and relevant DNS resolution.
3. Administrator assigns the target to one or more scanner accounts.
4. Assigned scanners see its history and permitted passive actions.

### 9.2 Discover, approve, and scan

1. Scanner launches passive discovery.
2. Trash Scan displays candidate assets; out-of-scope discoveries remain visibly unapproved.
3. Scanner configures Safe or Standard active scanning and completes the attestation.
4. Administrator receives an in-dashboard request and approves or denies it.
5. The job starts within the approval window, streams normalized progress, and remains cancellable.
6. On completion, Trash Scan normalizes results, compares them with the previous compatible scan, and records audit events.

### 9.3 Review change over time

The target timeline includes scan executions, assets first/last seen, findings first observed, severity changes, approvals, cancellations, timeouts, and exports. Against a compatible prior scan, findings are classified as:

- `NEW`
- `STILL_OBSERVED`
- `CHANGED`
- `NOT_OBSERVED`

A missing finding is never automatically called resolved. `NOT_OBSERVED` means only that the later scan did not observe it.

## 10. Scan lifecycle

| State | Meaning | Permitted next states |
|---|---|---|
| `DRAFT` | Request is incomplete or unsubmitted | `AWAITING_APPROVAL`, `CANCELLED` |
| `AWAITING_APPROVAL` | Active request needs an administrator decision | `APPROVED`, `DENIED`, `CANCELLED`, `EXPIRED` |
| `APPROVED` | Execution may begin within two hours | `QUEUED`, `CANCELLED`, `EXPIRED` |
| `QUEUED` | Waiting for worker capacity and limits | `RUNNING`, `CANCELLED`, `EXPIRED` |
| `RUNNING` | At least one tool stage is executing | `COMPLETED`, `FAILED`, `CANCELLING`, `TIMED_OUT` |
| `CANCELLING` | Process-tree termination is underway | `CANCELLED`, `FAILED` |
| `COMPLETED` | Planned stages ended and results were normalized | Terminal |
| `FAILED` | Execution or parsing ended unexpectedly | Terminal; new request may be created |
| `TIMED_OUT` | Maximum runtime was reached | Terminal; partial results retained |
| `DENIED` | Administrator declined execution | Terminal |
| `EXPIRED` | Approval was not consumed in time | Terminal |
| `CANCELLED` | Execution was withdrawn or stopped | Terminal |

## 11. Functional requirements

Priority values: **Must**, **Should**, and **Could**.

### 11.1 Authentication and authorization

| ID | Requirement | Priority |
|---|---|---|
| AUTH-01 | Support local Administrator and Scanner accounts. | Must |
| AUTH-02 | Enforce role and target assignment for every protected backend action. | Must |
| AUTH-03 | A Scanner may list, view, scan, compare, and export assigned targets only. | Must |
| AUTH-04 | An Administrator may disable an account and invalidate its active sessions. | Must |
| AUTH-05 | Never log plaintext passwords or session tokens. | Must |
| AUTH-06 | Record successful and failed authentication events without recording credentials. | Must |

### 11.2 Targets and scope

| ID | Requirement | Priority |
|---|---|---|
| SCOPE-01 | Allow an Administrator to configure one or more private IPv4 CIDRs. | Must |
| SCOPE-02 | Restrict public-target creation to Administrators using a checkbox and typed attestation. | Must |
| SCOPE-03 | Reject active execution outside approved boundaries or inside any deny rule. | Must |
| SCOPE-04 | Do not transfer active authorization to discovered assets, DNS results, or redirects. | Must |
| SCOPE-05 | Support exact IPv4, IPv4 CIDR, domain, and subdomain target records. | Must |
| SCOPE-06 | Support configurable government, military, healthcare, domain, IP, and CIDR deny rules. | Must |
| SCOPE-07 | Re-resolve names and re-evaluate scope immediately before active execution. | Must |

### 11.3 Scan lifecycle

| ID | Requirement | Priority |
|---|---|---|
| SCAN-01 | Provide Passive, Safe active, and Standard active profiles. | Must |
| SCAN-02 | Require a typed attestation and fresh Administrator approval for every active execution. | Must |
| SCAN-03 | Expire an unused active approval two hours after approval. | Must |
| SCAN-04 | Enforce a two-hour maximum runtime independently of approval expiry. | Must |
| SCAN-05 | Allow a Scanner to cancel their scan and an Administrator to stop any scan. | Must |
| SCAN-06 | Cancellation must terminate child processes, stop downstream stages, retain partial results, and audit the reason. | Must |
| SCAN-07 | Pause every scheduled active occurrence until approved. | Must |
| SCAN-08 | Enforce global and per-target concurrency and rate limits in the worker. | Must |
| SCAN-09 | Prevent retries from exceeding configured request, concurrency, and runtime limits. | Must |
| SCAN-10 | Record tool versions, template-set hash, profile, normalized arguments, and parser version. | Must |

### 11.4 Findings and history

| ID | Requirement | Priority |
|---|---|---|
| FIND-01 | Normalize tool output into assets, services, observations, findings, and evidence. | Must |
| FIND-02 | Record source tool, rule/template, severity, target, first seen, last seen, status, and an evidence summary for each finding. | Must |
| FIND-03 | Compare compatible scans using New, Still observed, Changed, and Not observed. | Must |
| FIND-04 | Never present Not observed as verified remediation. | Must |
| FIND-05 | Filter results by target, scan, date, tool, port, service, severity, and comparison status. | Should |
| FIND-06 | Retain bounded raw tool output with the scan until the corresponding results are deleted. | Should |
| FIND-07 | Display tool errors and incomplete stages so an incomplete scan cannot appear authoritative. | Must |

### 11.5 Scheduling and notifications

| ID | Requirement | Priority |
|---|---|---|
| SCHED-01 | Support immediate and recurring passive or active schedules. | Must |
| SCHED-02 | Store schedule times with an explicit timezone and store execution timestamps in UTC. | Must |
| SCHED-03 | Prevent overlapping executions for the same schedule unless an Administrator explicitly permits them. | Must |
| NOTIF-01 | Provide dashboard-only notifications and an unread count. | Must |
| NOTIF-02 | Present pending active approvals prominently to Administrators. | Must |
| NOTIF-03 | Notify the requester when a request is approved, denied, expired, started, completed, failed, cancelled, or timed out. | Must |
| NOTIF-04 | Never reveal unassigned target details in a Scanner notification. | Must |

### 11.6 Reports and exports

| ID | Requirement | Priority |
|---|---|---|
| RPT-01 | Generate a PDF report for a selected target or execution. | Must |
| RPT-02 | Include scope, authorization metadata, profile, limitations, asset summary, findings, changes, and timestamps. | Must |
| RPT-03 | Export normalized scans, assets, services, and findings as UTF-8 CSV. | Must |
| RPT-04 | Apply assignment authorization to every export and create a permanent audit event. | Must |
| RPT-05 | Label automated findings as indicators that require validation. | Must |
| RPT-06 | Escape formula-leading untrusted CSV values to prevent spreadsheet formula injection. | Must |

## 12. Tool bundle and restrictions

The approved bundle is Nmap, Subfinder, dnsx, ProjectDiscovery httpx, and restricted Nuclei. Scanner binaries and templates must be pinned and included in the worker image; the application must not download tools during a scan.

### 12.1 Nmap

**Approved responsibilities**

- TCP port discovery.
- TCP SYN scanning in the Standard profile.
- Service and version estimation.
- Operating-system estimation with confidence and limitations.
- Machine-readable XML output for ingestion.

**Restrictions**

- No spoofing, decoys, packet fragmentation, or evasion-oriented options.
- No user-supplied arbitrary command flags.
- No NSE script except scripts on an Administrator-reviewed allowlist.
- No credential, brute-force, exploit, intrusive, or denial-of-service NSE categories.
- UDP scanning is deferred.

### 12.2 Subfinder

**Approved responsibility:** passive public subdomain discovery.

**Restrictions**

- Enable only free/keyless sources in the MVP.
- Do not automatically enroll in providers or transmit API keys.
- Treat returned names as discoveries, not automatically authorized targets.

### 12.3 dnsx

**Approved responsibilities**

- Resolve and validate A, AAAA metadata, CNAME, PTR, MX, NS, TXT, SRV, SOA, and CAA records where applicable.
- Support Administrator-defined internal DNS resolvers for the lab.

**Restrictions**

- Disable wordlist and DNS brute-force modes.
- Apply rate limits and bounded retries.
- Never convert a DNS response into active scope automatically.

### 12.4 ProjectDiscovery httpx

**Approved responsibilities**

- HTTP/HTTPS reachability.
- Status code, title, content type, server header, redirect, response time, TLS metadata, and technology indicators.

**Restrictions**

- Probe only approved hosts and addresses.
- Bound redirects, response bytes, retries, timeouts, paths, and request rate.
- Revalidate redirect destinations before following them.
- Do not expose raw requests, arbitrary methods, arbitrary paths, unsafe mode, or user-defined headers in the MVP.
- Do not confuse this tool with the Python `httpx` client library.

### 12.5 Nuclei

**Approved responsibility:** reviewed detection of exposures and configuration indicators.

**Restrictions**

- Use an immutable Administrator-approved template allowlist.
- Exclude credential checks, fuzzing, brute force, code execution, exploit workflows, denial-of-service checks, intrusive templates, and arbitrary user templates.
- Disable automatic template and binary updates.
- Require explicit review before headless templates or multi-step workflows are added.
- Store the template identifier, template content hash, severity, matcher summary, and evidence for every result.

### 12.6 Version and template governance

- Pin tool versions in the worker image.
- Copy the reviewed Nuclei allowlist into the image by immutable version or content hash.
- Provide an Administrator maintenance action showing current and proposed tool versions and a template-set diff.
- Perform updates only through a controlled image rebuild or reviewed import after Administrator approval.
- Never change tool or template versions for a running execution.
- Record update approval and final versions in the permanent audit chain.

## 13. Command execution baseline

Per-scan ephemeral container isolation is deferred, but safe process invocation is mandatory and release-blocking.

- Invoke fixed executable paths using operating-system argument arrays.
- Never concatenate user input into a shell command.
- Never use `shell=True`, `cmd.exe`, PowerShell interpolation, or an equivalent command string for scanner execution.
- Parse targets into canonical IP, CIDR, or domain types before using them.
- Map UI options to a fixed internal allowlist of tool arguments.
- Do not let users choose arbitrary flags, files, templates, output paths, environment variables, resolvers, or executable paths.
- Create a unique bounded result directory for each execution.
- Treat stdout, stderr, XML, JSONL, HTTP metadata, titles, headers, and evidence as untrusted input.
- Terminate the complete subprocess tree on cancellation, emergency stop, timeout, or worker shutdown.

## 14. User experience

### 14.1 Primary areas

| Area | Contents |
|---|---|
| Dashboard | Assigned-target summary, running jobs, recent findings, schedules, notifications, and Administrator approval queue |
| Targets | Scope, assignment, passive discovery, services, current findings, history, and comparison |
| Scans | Queue, profile, stages, versions, limits, progress, cancellation, and partial results |
| Approvals | Requester, attestation, resolved scope, profile, ports, rate, schedule, expiry, and decision |
| Findings | Searchable normalized findings with evidence, timeline, and comparison status |
| Reports | PDF generation, CSV exports, status, and export history |
| Administration | Accounts, assignments, scope, deny rules, limits, tools, templates, audit verification, and retention |

### 14.2 Visual direction

Trash Scan should balance a professional security dashboard with restrained raccoon personality.

- Use charcoal, forest green, muted sage, off-white, and amber accents.
- Use raccoon and trash-can motifs for empty states, loading states, onboarding, and small navigation accents.
- Do not use playful language for severity, authorization, target blocking, termination, or errors.
- Use literal status names such as Pending approval, Running, Cancelling, Timed out, and Not observed.
- Keep the main dashboard information-dense but calm, with progressive disclosure for raw evidence.
- Honor reduced-motion preferences and keep progress understandable without animation.
- Provide keyboard navigation, visible focus, adequate contrast, text alternatives, and non-color status indicators.
- Design desktop-first for the Windows workstation while remaining responsive at tablet widths.

### 14.3 Dashboard notifications

Notifications exist only inside Trash Scan. There is no email, SMS, Slack, or operating-system notification in the MVP.

**Administrator notifications**

- Active execution awaiting approval.
- Public target added or disabled.
- Emergency termination.
- Repeated worker failure.
- Tool/template maintenance proposed.
- Audit-chain verification failure.

**Scanner notifications**

- Request approved, denied, cancelled, or expired.
- Scan started, completed, failed, cancelled, or timed out.
- Schedule paused pending approval.
- Report or export ready.

## 15. Findings and comparison

### 15.1 Normalized entities

- **Target:** user-managed authorized boundary.
- **Asset:** observed IP or hostname associated with a target.
- **Service:** protocol, port, state, probable product, version, and confidence.
- **Observation:** informational metadata such as DNS, HTTP header, TLS, or technology evidence.
- **Finding:** security-relevant indicator emitted by an approved rule or template.
- **Evidence:** bounded, escaped supporting data with sensitive content minimized.

### 15.2 Finding identity

A stable finding fingerprint should combine:

- Logical target ID.
- Normalized asset identity.
- Source tool.
- Rule or template identifier.
- Protocol and port, when applicable.
- Stable evidence key.

Volatile timestamps, random response values, and free-form evidence text must not create a new identity.

### 15.3 Comparison eligibility

Compare an execution only with a previous execution whose target boundary and relevant profile are compatible. If ports, templates, or stages differ materially, show the limitation or decline to classify absent findings. An incomplete or failed stage cannot establish `NOT_OBSERVED` for findings owned by that stage.

## 16. Reports and exports

### 16.1 PDF report

The report must include:

1. Trash Scan branding, target, scope, report time, requester, and profile.
2. Authorization time, approving Administrator, approved boundary, and attestation reference.
3. Executive summary with counts by severity and comparison status.
4. Explicit limitations of automated, unauthenticated reconnaissance.
5. Asset inventory: hosts, names, ports, probable services, web technologies, and confidence.
6. Findings: severity, affected asset, evidence summary, first/last observed, source, and comparison status.
7. Change summary against the previous compatible execution.
8. Methodology appendix: tool versions, template-set hash, timing, limits, incomplete stages, and errors.

### 16.2 CSV exports

Provide stable UTF-8 exports at minimum for:

- `scans.csv`
- `assets.csv`
- `services.csv`
- `findings.csv`

Escape cells beginning with spreadsheet formula characters when the value came from a target or tool. Exports must respect role and assignment authorization.

## 17. Data model and retention

| Entity | Purpose | Retention |
|---|---|---|
| User and role | Authentication, authorization, ownership | Until Administrator deletion; audit references remain |
| Target and scope rule | Canonical target, allow/deny decision, ownership attestation | Until Administrator deletion |
| Assignment | Scanner-to-target visibility | Current record plus permanent audit history |
| Scan request and approval | Profile, attestation, decision, expiry | Permanent as audit-linked records |
| Scan execution | State, limits, versions, timestamps, termination | Until related results are deleted; audit summary remains |
| Asset, service, observation, finding | Normalized reconnaissance result | Until Administrator deletion |
| Raw output and generated report | Evidence and export artifact | Until corresponding results are deleted |
| Operational log | Debug and worker diagnostics | Seven days |
| Audit event | Tamper-evident accountability chain | Permanent |
| Dashboard notification | In-app attention state | Seven days after read; audit event remains |

Deletion of targets or results must require Administrator confirmation, identify what will be removed, and produce a permanent audit event without retaining deleted sensitive evidence inside that event.

## 18. Tamper-evident audit trail

Every security-relevant event is appended to a hash chain. Each event includes:

- Monotonically increasing sequence number.
- UTC timestamp.
- Actor or system identity.
- Action type.
- Relevant object identifiers.
- Canonical event payload.
- Previous event hash.
- Current `SHA-256(previous_hash || canonical_event)` value.

Audit at least:

- Authentication outcomes.
- Account and role changes.
- Assignments.
- Target, allowlist, and denylist changes.
- Attestations, approvals, denials, and expirations.
- Scan lifecycle events and termination reasons.
- Rate, concurrency, and runtime changes.
- Reports and exports.
- Deletions.
- Tool and template maintenance.
- Audit verification results.

Audit events cannot be edited or deleted through the application. Verification recomputes the chain and creates a high-priority Administrator notification if it fails. Do not include passwords, sessions, secrets, arbitrary HTTP bodies, or full command output.

This design is tamper-evident, not tamper-proof. A Windows or database administrator can ultimately rewrite local storage. The application must communicate this limitation accurately.

## 19. Recommended architecture

| Component | Recommended technology | Responsibility |
|---|---|---|
| Web client | React, TypeScript, Vite | Responsive dashboard and administration |
| API | Python FastAPI | Validation, authorization, domain logic, endpoints, report requests |
| Database | PostgreSQL | Durable state, findings, approvals, schedules, notifications, audit chain |
| Queue and scheduler | Redis and Celery | Execution queue, schedules, concurrency, cancellation coordination |
| Scan worker | Python plus pinned CLI tools | Process lifecycle, safe arguments, parsing, normalization, progress |
| Reports | Jinja2 HTML and WeasyPrint; Python CSV | Reproducible PDF and normalized CSV exports |
| Deployment | Docker Compose on Docker Desktop | API, UI, database, Redis, and worker lifecycle |

### 19.1 Deployment constraints

- Use persistent Docker volumes for PostgreSQL and generated artifacts.
- Keep scanner binaries and templates in a pinned worker image.
- Do not implement self-updating application or scanner containers.
- SYN scanning and OS detection require raw-packet access. Grant only the minimum Docker capability proven necessary by the architecture spike.
- Docker Desktop, WSL networking, NAT, Windows Firewall, and the lab hypervisor may affect reachability and OS-detection accuracy.
- Report uncertainty rather than treating a missing response as proof that an asset or vulnerability does not exist.
- Document database-volume backup and restore. Automated backup orchestration is not required in the MVP.

## 20. Security and privacy requirements

- Validate and canonicalize IP, CIDR, domain, schedule, port, rate, and concurrency input on the server.
- Re-resolve domain names immediately before active execution and enforce scope against every address and redirect.
- Use fixed executables, allowlisted options, safe argument arrays, isolated output paths, bounded files, and sanitized environments.
- Encrypt browser traffic when the dashboard is accessed beyond localhost; document a local TLS or trusted reverse-proxy option.
- Use least-privilege database credentials and never bake secrets into images.
- Escape tool output in the UI and reports.
- Apply response-size, file-count, disk, CPU, memory, process, retry, concurrency, and runtime limits.
- Make emergency termination stop the full process tree and prevent later stages.
- Do not claim regulatory certification. Use least privilege, auditability, data minimization, secure defaults, and accessibility as engineering principles.

## 21. Performance and reliability requirements

| ID | Requirement | Priority |
|---|---|---|
| NFR-01 | Cached dashboard and target API requests should complete within 300 ms at p95 on the local deployment, excluding scans and report generation. | Should |
| NFR-02 | Acknowledge submission, approval, cancellation, and emergency-stop requests within two seconds. | Must |
| NFR-03 | Display a worker state change in the UI within five seconds. | Should |
| NFR-04 | After worker restart, reconcile an execution or mark it Failed; never assume completion. | Must |
| NFR-05 | Use conservative Administrator-configurable concurrency defaults without exposing arbitrary tool flags. | Must |
| NFR-06 | Parsers must tolerate malformed, truncated, and unexpected tool output without crashing the API. | Must |
| NFR-07 | Store timestamps in UTC and render them in the user-selected or browser-local timezone. | Must |
| NFR-08 | Make all terminal states idempotent so duplicate queue messages cannot duplicate findings or audit events. | Must |

## 22. Concurrency and rate controls

The Administrator can configure conservative limits without entering arbitrary tool arguments.

Required controls:

- Maximum simultaneous scan executions globally.
- Maximum simultaneous execution per target.
- Maximum parallel tool stages per execution.
- Nmap timing/profile mapping chosen from product-defined options.
- DNS queries per second.
- HTTP requests per second and per host.
- Nuclei requests per second and per host.
- Retry count and backoff.
- Maximum response bytes and stored evidence bytes.
- Maximum runtime of two hours.

Initial numeric defaults should be finalized during the architecture spike using the student lab’s capacity. The system must ship with conservative values and must not silently substitute a tool’s more aggressive defaults.

## 23. Cancellation and emergency termination

### 23.1 Normal cancellation

A Scanner can cancel an execution they started. An Administrator can cancel any execution. Cancellation must:

1. Atomically mark cancellation as requested.
2. Prevent the queue from starting new stages.
3. Send graceful termination to the active process group.
4. Force termination after a short configurable grace period.
5. Collect valid bounded partial outputs.
6. Mark incomplete stages clearly.
7. Produce one terminal state and one permanent audit event.

### 23.2 Emergency stop

An Administrator emergency stop has priority over ordinary queue work. It must terminate all active scanner process groups selected by the Administrator and prevent scheduled jobs from starting until the stop condition is cleared. The dashboard must show whether termination is requested, confirmed, or failed.

## 24. Acceptance criteria

The MVP is accepted only when all of the following are demonstrated:

- A clean Docker Desktop environment can start Trash Scan through documented Docker Compose commands and complete first-Administrator setup.
- An Administrator can configure a private lab CIDR, create a Scanner, assign a target, and verify that an unassigned Scanner cannot access the target through either UI or API.
- A Scanner can run passive discovery immediately on an assigned target.
- No active tool stage starts without a typed attestation and a fresh Administrator approval.
- An unused approval expires after two hours and cannot be replayed.
- A started scan may continue after approval expiry but is terminated at its two-hour runtime limit.
- Every scheduled active occurrence pauses until separately approved.
- Safe and Standard profiles invoke only product-approved options and tools.
- Standard supports SYN and OS detection where Docker Desktop and the lab network permit raw packets.
- Out-of-scope IPs and configured government, military, and healthcare deny rules reject execution before tool launch.
- DNS results and redirects are rechecked and cannot expand scope automatically.
- DNS wordlist enumeration and every prohibited testing category are absent from routes, UI controls, worker parameters, and default configurations.
- Cancellation and emergency stop terminate the process tree, block downstream stages, retain partial results, and reach an accurate terminal state.
- Comparable repeated scans produce New, Still observed, Changed, and Not observed classifications.
- Failed or incomplete stages do not incorrectly mark their previous findings Not observed.
- PDF and CSV exports include only data the requesting user may access.
- CSV export neutralizes untrusted formula-leading values.
- Audit verification passes for intact data and fails visibly after a controlled test mutation.
- No scan automatically downloads a binary or template.
- Every execution records pinned versions and a template-set hash.
- The interface passes keyboard navigation, focus visibility, reduced-motion, and contrast checks for core workflows.

## 25. Delivery plan

### Phase 0 — Architecture spike

Validate the uncertain platform behaviors before building the full interface:

- Docker Desktop connectivity to each virtual lab segment.
- Internal DNS resolver access.
- Nmap TCP connect behavior.
- Nmap SYN and OS detection with minimum raw-packet capability.
- Reliable process-tree cancellation and emergency termination.
- Machine-readable output and parser fixtures for every approved tool.

**Exit condition:** The team records a supported network configuration and proves active-process termination in the lab.

### Phase 1 — Foundation

- Docker Compose services.
- Local accounts and role enforcement.
- Targets, assignments, private allowlist, public exception, and deny rules.
- Hash-chained audit events.
- Seed data and fake scanner adapter.

**Exit condition:** Backend authorization and scope-boundary tests pass.

### Phase 2 — Passive discovery

- Subfinder adapter.
- dnsx adapter and internal resolver configuration.
- Asset normalization.
- Target history and passive schedules.

**Exit condition:** An assigned Scanner can complete passive discovery without active approval, while discovered assets remain unapproved.

### Phase 3 — Active workflow

- Attestation form.
- Administrator approval queue and notifications.
- Celery execution lifecycle.
- Nmap and httpx adapters.
- Safe and Standard profiles.
- Cancellation, emergency stop, rate limits, concurrency, approval expiry, and runtime enforcement.

**Exit condition:** Active lifecycle and process termination pass end-to-end tests.

### Phase 4 — Findings and comparison

- Restricted Nuclei adapter.
- Finding normalization and evidence.
- Stable fingerprints.
- Compatible-baseline logic.
- New, Still observed, Changed, and Not observed states.

**Exit condition:** Repeated-scan comparison is deterministic and handles incomplete scans correctly.

### Phase 5 — Reporting and hardening

- PDF reports and CSV exports.
- Retention cleanup for seven-day data.
- Tool/template maintenance workflow.
- Backup and restore documentation.
- Accessibility and responsive-design review.
- Final security and acceptance testing.

**Exit condition:** Every MVP acceptance criterion passes in the target Windows/Docker lab.

## 26. Vibe-coding guardrails

Because the project will be built with substantial AI coding assistance:

- Build vertical slices and keep the application runnable after each slice. Do not ask an AI to generate the entire system in one unreviewed change.
- Write schema migrations and backend authorization tests before building convenience UI around a feature.
- Create adversarial tests for IP/CIDR boundaries, DNS rebinding, redirects, assignment bypass, expired approvals, replayed approvals, and malformed tool output.
- Keep every scanner behind a common adapter interface.
- Store sanitized representative XML/JSONL output fixtures so parsers can be tested without sending network traffic.
- Use a fake scanner adapter and seeded targets for frontend work.
- Require human review for scope checks, authorization, subprocess execution, Docker capabilities, template changes, deletion, and audit-chain code.
- Pin Python, JavaScript, OS package, scanner, and template dependencies.
- Run formatter, linter, type checker, unit tests, integration tests, dependency review, and secret scanning in continuous integration.
- Treat AI-generated code and explanations as untrusted until verified against tests and official tool documentation.
- Do not paste real secrets, public-target attestations, or sensitive scan evidence into external AI prompts.

## 27. Testing strategy

### 27.1 Unit tests

- IP, CIDR, and domain canonicalization.
- Allow/deny precedence.
- Public-target boundaries.
- Role and assignment policies.
- Attestation invalidation.
- Approval expiry and consumption.
- State transitions and idempotency.
- Finding fingerprints and comparison.
- Audit canonicalization and chain verification.
- CSV formula neutralization.
- Tool-output parsers using fixtures.

### 27.2 Integration tests

- API, PostgreSQL, Redis, scheduler, and worker lifecycle.
- Domain resolution followed by scope rejection.
- Redirect to an out-of-scope address.
- Approved scan start and replay rejection.
- Scheduled active occurrence waiting for approval.
- Process-tree cancellation, timeout, and emergency stop.
- Tool failure and malformed/truncated output.
- PDF/CSV authorization filtering.
- Retention cleanup without audit deletion.

### 27.3 End-to-end lab tests

- Known open and closed TCP ports.
- Known HTTP headers and technology fingerprints.
- A controlled safe Nuclei match.
- A target changing between two scans.
- A previous finding becoming Not observed.
- SYN and OS detection under the documented Docker Desktop topology.
- A deliberately prohibited or out-of-scope target rejected before launch.

Tests must use systems owned by the team inside the authorized lab.

## 28. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Docker Desktop cannot reach every lab segment | Incomplete or misleading results | Complete the Phase 0 network spike; document routes and expose reachability diagnostics |
| Raw-packet capability is broader than desired | Worker compromise gains extra network capability | Grant the minimum proven capability; separate worker service; defer unsupported modes rather than over-privilege |
| Automated findings are false positives | Students may treat an indicator as proof | Restricted templates, evidence, confidence, limitations, and “requires validation” language |
| Sector blocklist misses a prohibited target | Policy boundary may fail | Private-only default, explicit public approval, configurable deny rules, resolution checks, permanent audit |
| DNS or redirect changes after approval | Traffic leaves approved scope | Re-resolve and revalidate immediately before each active stage and redirect |
| Cancellation leaves a child process running | Continued unwanted traffic | Process groups, graceful then forced termination, integration tests, status telemetry |
| Local administrator rewrites audit storage | History can be rewritten | Accurately state tamper-evident limitation; consider external signed checkpoints later |
| Tool or template drift | Unexpected behavior and irreproducible findings | Pinned worker image, immutable hashes, explicit maintenance, version capture |
| Vibe-coded authorization regression | Cross-target exposure or unintended scanning | Deny-by-default service layer, API policy tests, adversarial cases, mandatory review areas |
| Disk growth from retained results | Application or host instability | Per-execution output limits, storage dashboard, explicit deletion, backup guidance |

## 29. Deferred backlog

- IPv6 target and CIDR support.
- Per-scan ephemeral worker containers and network egress enforcement.
- External notifications.
- SSO, MFA, and multi-team tenancy.
- Automated public-target ownership verification and authorization-document uploads.
- UDP scanning, screenshots, authenticated checks, and broader OSINT providers.
- OWASP Amass.
- Administrator-authored safe templates with review workflow.
- Signed external audit checkpoints and SIEM integration.

Exploitation, credential testing, brute force, fuzzing, denial-of-service, spoofing, decoys, fragmentation, and evasion remain outside scope unless governed by a future, separately reviewed PRD.

## 30. Final decisions and assumptions

| Decision | MVP position |
|---|---|
| Team model | One student team; no tenant boundary |
| Target model | Private IPv4 by default; Administrator-attested owned public targets by exception |
| Active approval | Fresh approval per execution; valid two hours to start |
| Maximum runtime | Two hours, measured from execution start |
| Scheduled attestation | Persistent while unchanged; each active occurrence still needs approval |
| Visibility | Scanner sees assigned targets only; Administrator sees all |
| Tool bundle | Nmap, Subfinder, dnsx, ProjectDiscovery httpx, restricted Nuclei |
| Updates | Pinned and manual; never during a scan |
| Notifications | Dashboard only |
| Finding absent later | Not observed; never automatically Resolved |
| Retention | Targets/results until deletion; operational logs seven days; audit permanent |
| Deployment | Docker Desktop on Windows; portable to Linux/Kali later |
| UI direction | Professional dark security dashboard with restrained raccoon personality |

## 31. Implementation conventions for AI coding agents

These conventions are requirements unless replaced by a reviewed architecture decision record.

- Prefer explicit domain services: `ScopeService`, `AuthorizationService`, `ScanService`, `ComparisonService`, and `AuditService`.
- Put authorization and scope checks inside services called by every API and worker path.
- Define scanner adapters through typed input/output models; do not pass database models directly to subprocess code.
- Store all enumerated states as stable uppercase values shown in this PRD.
- Use database transactions for approval consumption, state transitions, finding upserts, and audit append operations.
- Use an outbox or equivalent transactional mechanism when a committed database change must enqueue work.
- Make queue tasks idempotent and safe to receive more than once.
- Keep raw scanner output separate from normalized entities.
- Include target ID, execution ID, stage ID, and correlation ID in structured operational logs.
- Never use operational logs as the source of truth for authorization or audit history.
- Add a migration for every schema change; do not modify an existing applied migration.
- Do not add a scanner, flag, template, public data source, or network capability without an explicit allowlist change and tests.

## 32. References

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [ProjectDiscovery Subfinder documentation](https://docs.projectdiscovery.io/opensource/subfinder/overview)
- [ProjectDiscovery dnsx documentation](https://docs.projectdiscovery.io/opensource/dnsx/overview)
- [ProjectDiscovery httpx documentation](https://docs.projectdiscovery.io/opensource/httpx/overview)
- [ProjectDiscovery Nuclei documentation](https://docs.projectdiscovery.io/opensource/nuclei/overview)

---

**Authorization notice:** This PRD defines an educational defensive-reconnaissance product. It is not authorization to scan any network. Trash Scan’s technical controls supplement—and do not replace—the team’s responsibility to obtain and respect permission.
