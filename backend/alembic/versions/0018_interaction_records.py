"""PRD v2 Phase 20: guided-session interaction records

Revision ID: 0018_interaction_records
Revises: 0017_session_domain
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_interaction_records"
down_revision: str | None = "0017_session_domain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "interaction_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("lab_sessions.id"),
                  nullable=False, index=True),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("action_version", sa.String(16), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="REQUESTED"),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("effect_claim", sa.String(256), nullable=True),
        sa.Column("reason", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("session_id", "request_id", name="uq_interaction_request"),
    )


def downgrade() -> None:
    op.drop_table("interaction_records")
