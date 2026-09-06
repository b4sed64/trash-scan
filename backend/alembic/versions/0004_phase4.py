"""phase 4: findings, sightings, comparisons

Revision ID: 0004_phase4
Revises: 0003_phase3
Create Date: 2026-09-06
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_phase4"
down_revision: str | None = "0003_phase3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("service_id", sa.String(36), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("source_tool", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(160), nullable=False),
        sa.Column("template_hash", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("name", sa.String(256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("asset_value", sa.String(256), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=True),
        sa.Column("matcher_name", sa.String(128), nullable=True),
        sa.Column("evidence_summary", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_execution_id", sa.String(36), nullable=True),
        sa.Column("last_execution_id", sa.String(36), nullable=True),
        sa.UniqueConstraint("target_id", "fingerprint", name="uq_finding"),
    )
    op.create_index("ix_finding_target", "findings", ["target_id"])
    op.create_index("ix_finding_severity", "findings", ["severity"])

    op.create_table(
        "finding_sightings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"),
                  nullable=False),
        sa.Column("severity", sa.String(10), nullable=True),
        sa.Column("evidence_key", sa.String(200), nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("finding_id", "execution_id", name="uq_finding_sighting"),
    )

    op.create_table(
        "scan_comparisons",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("execution_id", sa.String(36), sa.ForeignKey("scan_executions.id"),
                  nullable=False),
        sa.Column("baseline_execution_id", sa.String(36),
                  sa.ForeignKey("scan_executions.id"), nullable=True),
        sa.Column("eligible", sa.Boolean(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("limitations", sa.JSON(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("execution_id", name="uq_comparison_execution"),
    )


def downgrade() -> None:
    for table in ("scan_comparisons", "finding_sightings", "findings"):
        op.drop_table(table)
