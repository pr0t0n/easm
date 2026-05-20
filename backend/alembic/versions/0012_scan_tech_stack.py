"""add tech_stack JSONB column to scan_jobs

Revision ID: 0012_scan_tech_stack
Revises: 0011_agent_trace_events
Create Date: 2026-05-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012_scan_tech_stack"
down_revision = "0011_agent_trace_events"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_jobs",
        sa.Column(
            "tech_stack",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.create_index(
        "ix_scan_jobs_tech_stack_gin",
        "scan_jobs",
        ["tech_stack"],
        postgresql_using="gin",
    )


def downgrade():
    op.drop_index("ix_scan_jobs_tech_stack_gin", table_name="scan_jobs")
    op.drop_column("scan_jobs", "tech_stack")
