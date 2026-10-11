"""PRD v2 Phase 11: candidate CVE associations (offline intelligence)

Revision ID: 0011_candidate_associations
Revises: 0010_canonical_issues
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_candidate_associations"
down_revision: str | None = "0010_canonical_issues"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "candidate_associations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False,
                  index=True),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issues.id"), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version_evidence", sa.String(128), nullable=True),
        sa.Column("matched_cpe", sa.String(256), nullable=True),
        sa.Column("version_range", sa.String(128), nullable=True),
        sa.Column("applicability", sa.String(16), nullable=False, server_default="CANDIDATE"),
        sa.Column("confidence", sa.String(16), nullable=True),
        sa.Column("cvss_version", sa.String(8), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("advisory_source", sa.String(256), nullable=True),
        sa.Column("match_rationale", sa.String(256), nullable=True),
        sa.Column("applicability_rule_version", sa.String(16), nullable=True),
        sa.Column("priority_lane", sa.String(20), nullable=True),
        sa.Column("priority_reasons", sa.JSON(), nullable=True),
        sa.Column("snapshot_version", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("target_id", "cve_id", "product", "version_evidence",
                            name="uq_candidate_association"),
    )


def downgrade() -> None:
    op.drop_table("candidate_associations")
