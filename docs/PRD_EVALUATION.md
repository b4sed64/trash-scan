# Trash Scan PRD — evaluation

An assessment of `Trash_Scan_PRD.md` v1.0 from an implementation standpoint: what is
strong, what is ambiguous, and where the risk concentrates. Written alongside the Phase 1
build.

## Overall

The PRD is unusually complete and internally consistent for a student project. Scope and
authorization are treated as product behaviour rather than a banner, the state machine is
fully enumerated, retention is specified per entity, and the delivery plan already
sequences the work into runnable vertical slices. The recommended architecture is
appropriate and the "vibe-coding guardrails" section is essentially a correct engineering
process.

It is also **large**. A faithful build of every Must requirement is a multi-month effort
for a student team. The phased plan is the right response; this repository follows it and
implements Phase 1 only.

## Strengths

- **Deny-first scope model** (6.4, 20) is specified precisely enough to implement and test
  directly. The "never send active traffic to an unresolved or ambiguous target" rule and
  the re-resolve-before-every-active-stage rule close the DNS-rebinding gap that most
  hobby scanners miss.
- **Separation of approval window (2h to start) from runtime cap (2h from RUNNING)** (8.3,
  30) is a genuinely good design and the PRD is careful to keep them distinct.
- **Audit chain** (18) is well specified: canonical payload, `SHA-256(prev || event)`,
  append-only, recompute-to-verify, and an honest statement that it is tamper-*evident*,
  not tamper-*proof*.
- **Tool restrictions** (12) are concrete: no `shell=True`, fixed arg arrays, option
  allowlist, pinned versions, immutable template hash, no in-scan downloads.
- **Findings comparison** (15) correctly refuses to call a missing finding "resolved" and
  refuses to classify absent findings when a stage failed.

## Ambiguities / decisions the build had to make

| # | Ambiguity | Resolution taken in Phase 1 |
|---|---|---|
| 1 | 5.2 says additional accounts are "created and disabled by an administrator." Unclear whether this means *created in a disabled state* or *an admin can disable them*. | New accounts are created **disabled**; an admin flips `is_active` to enable. Both readings are satisfied. |
| 2 | The exact wording of the two attestations (public-target and ethical-use) is not given. | Fixed canonical strings in `backend/app/constants.py`. Must be reviewed by the team; changing them is a one-line change plus a test update. |
| 3 | "Known government, military, and healthcare domains" — no list is provided, and the PRD itself admits classification is imperfect (6.3). | Shipped a small built-in suffix/exact denylist (`.gov`, `.mil`, `.gov.uk`, `.mod.uk`, `.nhs.uk`, `who.int`, …) marked immutable, plus admin-configurable rules. This is deliberately conservative and incomplete by design. |
| 4 | "Narrow public CIDR" (6.2) — no maximum prefix length defined. | Not enforced yet. Recommend capping public CIDRs at e.g. /24 in Phase 3 and recording the decision. |
| 5 | Session idle-expiration and absolute-lifetime values are not specified. | 30 min idle, 12 h absolute; both configurable via env. |
| 6 | Argon2id "conservative parameters" are not quantified. | t=3, m=64 MiB, p=2 by default; configurable. Finalize during the Phase 0 spike on lab hardware. |
| 7 | Whether a target must be in-scope to be *created* (vs. only to be *actively scanned*). | Targets can be created out of private scope (scope is enforced at active execution), but creation is rejected if the target matches a **deny** rule. |
| 8 | Audit `seq` monotonicity under concurrent writers. | Phase 1 computes `seq = max+1` inside the request transaction. Safe for the single-process API; the Celery worker in Phase 3 must serialize audit appends (advisory lock or a dedicated append service) — noted in code. |

## Risks the PRD identifies that remain real

- **Docker Desktop / WSL reachability and raw-packet capability** (19.1, 28) — genuinely
  uncertain and correctly gated behind the Phase 0 spike. Nothing in Phase 1 depends on
  it.
- **Sector denylist will miss organizations** — accepted and documented; the private-only
  default is the real safeguard.
- **Local admin can rewrite audit storage** — accepted; the UI states this.
- **Vibe-coded authorization regression** — mitigated here by a deny-by-default service
  layer that every route calls, plus adversarial API tests. This discipline must hold for
  every later phase.

## Recommendations for later phases

1. Do the Phase 0 spike **before** Phase 3. SYN/OS detection capability and process-tree
   termination are the two things most likely to invalidate assumptions.
2. Add a transactional outbox now-ish (Phase 2/3 boundary) rather than retrofitting it —
   the PRD already calls for it (31).
3. Keep the public-CIDR prefix cap, redirect-revalidation, and "resolved set changed since
   approval" checks together in `ScopeService` so there is exactly one place to review.
4. When Nuclei is added, store the template-set content hash in the same record as the
   scan execution and surface it in the report methodology appendix, as 12.5 / 16.1
   require.
5. Consider signed external audit checkpoints (29) sooner rather than later if the lab is
   ever graded on audit integrity.
