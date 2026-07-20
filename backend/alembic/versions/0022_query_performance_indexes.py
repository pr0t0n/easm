"""query performance indexes for paginated cockpit and quality metrics

Revision ID: 0022
Revises: 0021
"""
from alembic import op


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_findings_scan_open_severity_cvss_id",
        "findings",
        ["scan_job_id", "is_false_positive", "severity", "cvss", "id"],
        unique=False,
    )
    op.create_index(
        "ix_scan_work_items_scan_status_phase",
        "scan_work_items",
        ["scan_job_id", "status", "phase_id"],
        unique=False,
    )
    op.create_index(
        "ix_offensive_hypotheses_scan_status_confidence",
        "offensive_hypotheses",
        ["scan_job_id", "status", "confidence"],
        unique=False,
    )
    op.create_index(
        "ix_executed_tool_runs_scan_status",
        "executed_tool_runs",
        ["scan_job_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_executed_tool_runs_scan_status", table_name="executed_tool_runs")
    op.drop_index("ix_offensive_hypotheses_scan_status_confidence", table_name="offensive_hypotheses")
    op.drop_index("ix_scan_work_items_scan_status_phase", table_name="scan_work_items")
    op.drop_index("ix_findings_scan_open_severity_cvss_id", table_name="findings")
