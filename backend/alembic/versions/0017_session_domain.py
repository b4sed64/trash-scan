"""PRD v2 Phase 18: session grants, lab sessions, controller leases

Revision ID: 0017_session_domain
Revises: 0016_stream_events
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_session_domain"
down_revision: str | None = "0016_stream_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "session_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_id", sa.String(36), sa.ForeignKey("proof_plans.id"), nullable=False),
        sa.Column("transport", sa.String(48), nullable=False),
        sa.Column("listener_interface", sa.String(64), nullable=True),
        sa.Column("listener_port", sa.Integer(), nullable=True),
        sa.Column("guided_action_ids", sa.JSON(), nullable=True),
        sa.Column("budgets", sa.JSON(), nullable=True),
        sa.Column("lifetime_seconds", sa.Integer(), nullable=False, server_default="600"),
        sa.Column("idle_seconds", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("operator_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "lab_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("attempt_id", sa.String(36), sa.ForeignKey("proof_attempts.id"),
                  nullable=False, index=True),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("session_grants.id"), nullable=True),
        sa.Column("fixture_id", sa.String(36), sa.ForeignKey("lab_fixtures.id"), nullable=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("framework_epoch", sa.String(64), nullable=True),
        sa.Column("native_session_id", sa.String(64), nullable=True),
        sa.Column("transport", sa.String(48), nullable=True),
        sa.Column("observed_connection", sa.String(256), nullable=True),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("state", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("quarantine_reason", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "controller_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("lab_sessions.id"),
                  nullable=False, index=True),
        sa.Column("holder", sa.String(128), nullable=False),
        sa.Column("fencing_token", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("controller_leases")
    op.drop_table("lab_sessions")
    op.drop_table("session_grants")
