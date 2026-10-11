"""PRD v2 Phase 17: durable stream events for the live execution workspace

Revision ID: 0016_stream_events
Revises: 0015_proof_execution
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_stream_events"
down_revision: str | None = "0015_proof_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "stream_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("attempt_id", sa.String(36), sa.ForeignKey("proof_attempts.id"),
                  nullable=False, index=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("server_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("attempt_id", "seq", name="uq_stream_event_seq"),
    )


def downgrade() -> None:
    op.drop_table("stream_events")
