"""PRD v2 Phase 15: lab environment, fixtures, recovery records

Revision ID: 0014_lab_environment
Revises: 0013_exploitability_assessment
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_lab_environment"
down_revision: str | None = "0013_exploitability_assessment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "lab_environments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("provider", sa.String(32), nullable=True),
        sa.Column("egress_policy", sa.String(512), nullable=True),
        sa.Column("isolation_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("isolation_proof_ref", sa.String(256), nullable=True),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "lab_fixtures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("lab_environment_id", sa.String(36), sa.ForeignKey("lab_environments.id"),
                  nullable=False, index=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=True),
        sa.Column("build_id", sa.String(128), nullable=True),
        sa.Column("snapshot_id", sa.String(128), nullable=True),
        sa.Column("snapshot_digest", sa.String(128), nullable=True),
        sa.Column("baseline_health", sa.String(20), nullable=False, server_default="UNKNOWN"),
        sa.Column("restore_rehearsed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("restore_rehearsal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(64), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("target_id", name="uq_lab_fixture_target"),
    )
    op.create_table(
        "recovery_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fixture_id", sa.String(36), sa.ForeignKey("lab_fixtures.id"), nullable=False,
                  index=True),
        sa.Column("outcome", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("detail", sa.String(512), nullable=True),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("recovery_records")
    op.drop_table("lab_fixtures")
    op.drop_table("lab_environments")
