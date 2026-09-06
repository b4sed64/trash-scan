"""phase 5: reports, operational logs, maintenance proposals

Revision ID: 0005_phase5
Revises: 0004_phase4
Create Date: 2026-09-06
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_phase5"
down_revision: str | None = "0004_phase4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(12), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"), nullable=True),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "operational_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(8), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("target_id", sa.String(36), nullable=True),
        sa.Column("execution_id", sa.String(36), nullable=True),
        sa.Column("stage_id", sa.String(48), nullable=True),
        sa.Column("correlation_id", sa.String(48), nullable=True),
    )
    op.create_index("ix_oplog_ts", "operational_logs", ["ts"])
    op.create_table(
        "maintenance_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("current_state", sa.JSON(), nullable=True),
        sa.Column("proposed_state", sa.JSON(), nullable=True),
        sa.Column("state", sa.String(12), nullable=False),
        sa.Column("decided_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    for table in ("maintenance_proposals", "operational_logs", "reports"):
        op.drop_table(table)
