"""PRD v2 Phase 8: per-execution coverage ledger

Revision ID: 0009_coverage_ledger
Revises: 0008_port_set_protocol
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_coverage_ledger"
down_revision: str | None = "0008_port_set_protocol"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "coverage_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"),
                  nullable=False, index=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("check_family", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(256), nullable=True),
        sa.Column("evidence_ref", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("execution_id", "stage", "check_family", name="uq_coverage_entry"),
    )


def downgrade() -> None:
    op.drop_table("coverage_entries")
