"""phase 3: approvals, services, emergency stop

Revision ID: 0003_phase3
Revises: 0002_phase2
Create Date: 2026-09-06
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_phase3"
down_revision: str | None = "0002_phase2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("schedules.id"), nullable=True),
        sa.Column("occurrence_id", sa.String(36), nullable=True),
        sa.Column("profile", sa.String(20), nullable=False),
        sa.Column("attestation_text", sa.Text(), nullable=False),
        sa.Column("requested_options", sa.JSON(), nullable=True),
        sa.Column("scope_at_request", sa.JSON(), nullable=True),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("decided_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_approval_state", "scan_approvals", ["state"])

    op.create_table(
        "services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("target_id", "asset_id", "port", "protocol", name="uq_service"),
    )
    op.create_table(
        "emergency_stops",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_scope", sa.String(12), nullable=False),
        sa.Column("execution_ids", sa.JSON(), nullable=True),
        sa.Column("state", sa.String(12), nullable=False),
        sa.Column("note", sa.String(512), nullable=True),
        sa.Column("cleared_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("cleared_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    for table in ("emergency_stops", "services", "scan_approvals"):
        op.drop_table(table)
