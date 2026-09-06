"""phase 7: scan groups (one scan across many targets)

Revision ID: 0007_scan_groups
Revises: 0006_port_sets
Create Date: 2026-09-06
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_scan_groups"
down_revision: str | None = "0006_port_sets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_executions", sa.Column("scan_group_id", sa.String(36), nullable=True))
    op.add_column("scan_executions",
                  sa.Column("group_seq", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("scan_executions",
                  sa.Column("group_size", sa.Integer(), nullable=False, server_default="1"))
    op.create_index("ix_exec_scan_group", "scan_executions", ["scan_group_id"])

    op.add_column("scan_approvals", sa.Column("scan_group_id", sa.String(36), nullable=True))
    op.create_index("ix_approval_scan_group", "scan_approvals", ["scan_group_id"])

    # Back-fill: every existing execution becomes its own single-target group.
    op.execute("UPDATE scan_executions SET scan_group_id = id WHERE scan_group_id IS NULL")
    op.execute(
        "UPDATE scan_approvals SET scan_group_id = execution_id WHERE scan_group_id IS NULL"
    )


def downgrade() -> None:
    op.drop_index("ix_approval_scan_group", "scan_approvals")
    op.drop_column("scan_approvals", "scan_group_id")
    op.drop_index("ix_exec_scan_group", "scan_executions")
    op.drop_column("scan_executions", "group_size")
    op.drop_column("scan_executions", "group_seq")
    op.drop_column("scan_executions", "scan_group_id")
