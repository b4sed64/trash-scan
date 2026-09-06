"""phase 2: executions, observations, schedules

Revision ID: 0002_phase2
Revises: 0001_initial
Create Date: 2026-09-06
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_phase2"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("profile", sa.String(20), nullable=False),
        sa.Column("classification", sa.String(8), nullable=False),
        sa.Column("recurrence", sa.String(12), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=True),
        sa.Column("at_time", sa.String(5), nullable=True),
        sa.Column("timezone", sa.String(64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("overlap_policy", sa.String(8), nullable=True),
        sa.Column("options", sa.JSON(), nullable=True),
        sa.Column("options_hash", sa.String(64), nullable=True),
        sa.Column("attestation_text", sa.Text(), nullable=True),
        sa.Column("attested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "scan_executions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("schedules.id"), nullable=True),
        sa.Column("profile", sa.String(20), nullable=False),
        sa.Column("classification", sa.String(8), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("options", sa.JSON(), nullable=True),
        sa.Column("approval_id", sa.String(36), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("runtime_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cancel_reason", sa.String(256), nullable=True),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(36), nullable=True),
        sa.Column("stages", sa.JSON(), nullable=True),
        sa.Column("tool_versions", sa.JSON(), nullable=True),
        sa.Column("normalized_args", sa.JSON(), nullable=True),
        sa.Column("parser_version", sa.String(16), nullable=True),
        sa.Column("template_set_hash", sa.String(64), nullable=True),
        sa.Column("result_dir", sa.String(512), nullable=True),
    )
    op.create_index("ix_exec_state", "scan_executions", ["state"])
    op.create_index("ix_exec_target", "scan_executions", ["target_id"])

    op.create_table(
        "observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"), nullable=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("source_tool", sa.String(32), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("target_id", "kind", "key", "value", name="uq_observation"),
    )
    op.create_table(
        "schedule_occurrences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("schedules.id"), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"), nullable=True),
        sa.Column("note", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("schedule_id", "scheduled_for", name="uq_occurrence"),
    )


def downgrade() -> None:
    for table in (
        "schedule_occurrences",
        "observations",
        "scan_executions",
        "schedules",
    ):
        op.drop_table(table)
