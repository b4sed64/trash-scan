"""PRD v2 Phase 16: proof plans, attempts and evidence

Revision ID: 0015_proof_execution
Revises: 0014_lab_environment
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_proof_execution"
down_revision: str | None = "0014_lab_environment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "proof_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("fixture_id", sa.String(36), sa.ForeignKey("lab_fixtures.id"), nullable=False),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issues.id"), nullable=True),
        sa.Column("module_id", sa.String(128), nullable=False),
        sa.Column("options", sa.JSON(), nullable=True),
        sa.Column("proof_marker", sa.String(64), nullable=False),
        sa.Column("evaluator", sa.String(32), nullable=True),
        sa.Column("budgets", sa.JSON(), nullable=True),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("engagement_ref", sa.String(256), nullable=True),
        sa.Column("attestation_text", sa.Text(), nullable=True),
        sa.Column("operator_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="DRAFT"),
        sa.Column("approved_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "proof_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_id", sa.String(36), sa.ForeignKey("proof_plans.id"), nullable=False,
                  index=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="QUEUED"),
        sa.Column("proof_outcome", sa.String(28), nullable=True),
        sa.Column("recovery_outcome", sa.String(20), nullable=False, server_default="NOT_NEEDED"),
        sa.Column("blocked_reason", sa.String(512), nullable=True),
        sa.Column("measured_runtime_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "proof_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("attempt_id", sa.String(36), sa.ForeignKey("proof_attempts.id"), nullable=False,
                  index=True),
        sa.Column("marker", sa.String(64), nullable=True),
        sa.Column("demonstrated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("native_code", sa.String(32), nullable=True),
        sa.Column("negative_control_passed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("redacted_summary", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("proof_evidence")
    op.drop_table("proof_attempts")
    op.drop_table("proof_plans")
