"""Add ExecutedToolRun table for idempotency tracking

Revision ID: 0004_executed_tool_runs
Revises: 0003_finding_structured_columns
Create Date: 2026-04-06
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_executed_tool_runs"
down_revision = "0003_finding_structured_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create executed_tool_runs table to track tool execution for idempotency."""
    op.create_table(
        "executed_tool_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_job_id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="success"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("execution_time_seconds", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ),
        sa.PrimaryKeyConstraint("id")
    )
    # Indices for efficient querying
    op.create_index("ix_executed_tool_runs_scan_job_id", "executed_tool_runs", ["scan_job_id"])
    op.create_index("ix_executed_tool_runs_tool_name", "executed_tool_runs", ["tool_name"])
    op.create_index("ix_executed_tool_runs_target", "executed_tool_runs", ["target"])
    op.create_index("ix_executed_tool_runs_created_at", "executed_tool_runs", ["created_at"])


def downgrade() -> None:
    """Drop executed_tool_runs table."""
    op.drop_index("ix_executed_tool_runs_created_at", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_target", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_tool_name", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_scan_job_id", table_name="executed_tool_runs")
    op.drop_table("executed_tool_runs")
