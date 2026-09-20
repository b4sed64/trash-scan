"""post-MVP: protocol (TCP/UDP) on administrator-defined port sets

Revision ID: 0008_port_set_protocol
Revises: 0007_scan_groups
Create Date: 2026-09-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_port_set_protocol"
down_revision: str | None = "0007_scan_groups"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "port_sets",
        sa.Column("protocol", sa.String(3), nullable=False, server_default="TCP"),
    )


def downgrade() -> None:
    op.drop_column("port_sets", "protocol")
