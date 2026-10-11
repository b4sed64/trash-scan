"""PRD v2 Phase 9: canonical issues and occurrences

Creates the canonical projection tables only. Backfill of existing
Finding/FindingSighting rows is performed by the idempotent
``services/issues.py::backfill_all`` (admin-triggered / forward-derived), not in
this migration, so the migration stays static and fully reversible: downgrade
drops only the projection; the underlying findings are never touched.

Revision ID: 0010_canonical_issues
Revises: 0009_coverage_ledger
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_canonical_issues"
down_revision: str | None = "0009_coverage_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "issues",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("issue_type", sa.String(192), nullable=False),
        sa.Column("category", sa.String(48), nullable=True),
        sa.Column("title", sa.String(256), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False, server_default="INFO"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OBSERVED"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("target_id", "issue_type", name="uq_issue"),
    )
    op.create_table(
        "occurrences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issues.id"), nullable=False,
                  index=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"),
                  nullable=False, index=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("asset_value", sa.String(256), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(10), nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("issue_id", "execution_id", "finding_id", name="uq_occurrence_issue"),
    )


def downgrade() -> None:
    op.drop_table("occurrences")
    op.drop_table("issues")
