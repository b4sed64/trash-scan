"""PRD v2 Phase 12: issue review/remediation state + risk exceptions

Revision ID: 0012_issue_review
Revises: 0011_candidate_associations
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_issue_review"
down_revision: str | None = "0011_candidate_associations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("issues", sa.Column("validation_state", sa.String(16), nullable=False,
                                      server_default="UNREVIEWED"))
    op.add_column("issues", sa.Column("remediation_state", sa.String(20), nullable=False,
                                      server_default="OPEN"))
    op.add_column("issues", sa.Column("owner", sa.String(128), nullable=True))
    op.add_column("issues", sa.Column("due_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("issues", sa.Column("desired_state", sa.String(256), nullable=True))
    op.add_column("issues", sa.Column("remediation_plan", sa.Text(), nullable=True))
    op.add_column("issues", sa.Column("reopened", sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
    op.add_column("issues", sa.Column("closed_by_id", sa.String(36),
                                      sa.ForeignKey("users.id"), nullable=True))
    op.add_column("issues", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("issues", sa.Column("closure_reason", sa.String(512), nullable=True))
    op.add_column("issues", sa.Column("closure_evidence_ref", sa.String(256), nullable=True))
    op.add_column("issues", sa.Column("verification_method", sa.String(24), nullable=True))
    op.add_column("issues", sa.Column("manually_verified", sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
    op.create_table(
        "risk_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issues.id"), nullable=False,
                  index=True),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("scope", sa.String(256), nullable=True),
        sa.Column("compensating_controls", sa.String(512), nullable=True),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_table("risk_exceptions")
    for col in ("manually_verified", "verification_method", "closure_evidence_ref",
                "closure_reason", "closed_at", "closed_by_id", "reopened", "remediation_plan",
                "desired_state", "due_date", "owner", "remediation_state", "validation_state"):
        op.drop_column("issues", col)
