"""Coverage ledger derivation and persistence (PRD v2 §7, Phase 8).

Turns each stage's :class:`StageOutput` into a conservative coverage outcome so
that a clean ("no findings") result can be told apart from "we could not
actually check". The mapping is deliberately conservative: anything short of a
confirmed clean run is treated as not-fully-assessed, because over-claiming
coverage is the dangerous error (it would let an incomplete scan silently mark
real findings as resolved).

``coverage_outcome`` is a pure function shared by the real pipeline and the
tests; ``record_coverage`` writes the immutable :class:`CoverageEntry` rows.
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from ..models import CoverageEntry, ScanExecution

# Outcomes (see models.CoverageEntry).
ASSESSED = "ASSESSED"
COMPLETED_WITH_GAPS = "COMPLETED_WITH_GAPS"
NOT_ASSESSED = "NOT_ASSESSED"
INCONCLUSIVE = "INCONCLUSIVE"

# Only a fully-ASSESSED unit may establish a real negative (NOT_OBSERVED).
CLEARS_FINDINGS = ASSESSED


def coverage_outcome(out) -> tuple[str, str]:
    """Return ``(outcome, reason)`` for one stage output.

    Order matters — the checks run most-conservative-first:
    * a missing tool never ran, so the family was NOT_ASSESSED;
    * an incomplete run (timeout / truncation / budget) COMPLETED_WITH_GAPS;
    * a run that did not confirm success is INCONCLUSIVE;
    * a successful run that had nothing in scope to look at is NOT_ASSESSED
      (an exit-zero skipped check is not evidence of a clean target);
    * only a successful run with something to assess is ASSESSED.
    """
    stderr = (out.stderr_excerpt or "").lower()
    note = (out.note or "").strip()

    if "not found" in stderr and ("binary" in stderr or "worker image" in stderr):
        return NOT_ASSESSED, "tool unavailable"
    if out.incomplete:
        return COMPLETED_WITH_GAPS, (note or out.stderr_excerpt or "stage incomplete")[:256]
    if not out.ok:
        return INCONCLUSIVE, (note or out.stderr_excerpt or "stage did not confirm success")[:256]
    if note.lower().startswith("no "):
        # e.g. "no approved hosts to probe", "no resolved in-scope IPs to scan"
        return NOT_ASSESSED, note[:256]
    return ASSESSED, ""


def _evidence_ref(out) -> str:
    raw = getattr(out, "raw_path", None)
    return os.path.basename(raw) if raw else ""


def record_coverage(db: Session, execution: ScanExecution, stage_outputs) -> list[dict]:
    """Insert one immutable CoverageEntry per stage and return a JSON-friendly
    summary for embedding in ``ScanExecution.stages`` (so comparison and the API
    can read coverage without a second query)."""
    summary: list[dict] = []
    for out in stage_outputs:
        outcome, reason = coverage_outcome(out)
        # check_family defaults to the stage name; Phase 10 refines rule-families.
        family = out.stage
        db.add(CoverageEntry(
            execution_id=execution.id, target_id=execution.target_id,
            stage=out.stage, check_family=family, outcome=outcome,
            reason=reason, evidence_ref=_evidence_ref(out),
        ))
        summary.append({"stage": out.stage, "check_family": family,
                        "outcome": outcome, "reason": reason})
    return summary
