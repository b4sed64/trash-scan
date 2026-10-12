"""PRD v2 Phase 22: administrator terminal grants + frame receipts

Revision ID: 0020_terminal
Revises: 0019_session_evidence
Create Date: 2026-10-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_terminal"
down_revision: str | None = "0019_session_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "terminal_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("lab_sessions.id"),
                  nullable=False, index=True),
        sa.Column("admin_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("attestation", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "terminal_frame_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("lab_sessions.id"),
                  nullable=False, index=True),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("terminal_grants.id"), nullable=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("input_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("session_id", "request_id", name="uq_terminal_frame"),
    )


def downgrade() -> None:
    op.drop_table("terminal_frame_receipts")
    op.drop_table("terminal_grants")
