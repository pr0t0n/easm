"""Add rich execution keys to executed tool runs.

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("executed_tool_runs", sa.Column("phase_id", sa.String(length=10), nullable=True))
    op.add_column("executed_tool_runs", sa.Column("skill_id", sa.String(length=120), nullable=True))
    op.add_column("executed_tool_runs", sa.Column("profile", sa.String(length=120), nullable=True))
    op.add_column("executed_tool_runs", sa.Column("execution_key", sa.String(length=160), nullable=True))
    op.add_column("executed_tool_runs", sa.Column("arguments_hash", sa.String(length=80), nullable=True))
    op.create_index("ix_executed_tool_runs_phase_id", "executed_tool_runs", ["phase_id"])
    op.create_index("ix_executed_tool_runs_skill_id", "executed_tool_runs", ["skill_id"])
    op.create_index("ix_executed_tool_runs_profile", "executed_tool_runs", ["profile"])
    op.create_index("ix_executed_tool_runs_execution_key", "executed_tool_runs", ["execution_key"])
    op.drop_constraint("uq_executed_tool_runs_scan_tool_target", "executed_tool_runs", type_="unique")
    op.create_unique_constraint(
        "uq_executed_tool_runs_scan_execution_key",
        "executed_tool_runs",
        ["scan_job_id", "execution_key"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_executed_tool_runs_scan_execution_key", "executed_tool_runs", type_="unique")
    op.create_unique_constraint(
        "uq_executed_tool_runs_scan_tool_target",
        "executed_tool_runs",
        ["scan_job_id", "tool_name", "target"],
    )
    op.drop_index("ix_executed_tool_runs_execution_key", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_profile", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_skill_id", table_name="executed_tool_runs")
    op.drop_index("ix_executed_tool_runs_phase_id", table_name="executed_tool_runs")
    op.drop_column("executed_tool_runs", "arguments_hash")
    op.drop_column("executed_tool_runs", "execution_key")
    op.drop_column("executed_tool_runs", "profile")
    op.drop_column("executed_tool_runs", "skill_id")
    op.drop_column("executed_tool_runs", "phase_id")
