"""PRD v2 Phase 21: session evidence

Revision ID: 0019_session_evidence
Revises: 0018_interaction_records
Create Date: 2026-10-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_session_evidence"
down_revision: str | None = "0018_interaction_records"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "session_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("lab_sessions.id"),
                  nullable=False, index=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("seq_start", sa.Integer(), nullable=True),
        sa.Column("seq_end", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(128), nullable=True),
        sa.Column("evaluator", sa.String(64), nullable=True),
        sa.Column("effect_claim", sa.String(256), nullable=True),
        sa.Column("limitations", sa.String(256), nullable=True),
        sa.Column("demonstrated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("session_evidence")
