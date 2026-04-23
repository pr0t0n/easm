"""scan_audit_logs table: operational memory for autonomous agent

Revision ID: 0006
Revises: 0005_scan_job_target_query_text
Create Date: 2026-04-23
"""
from alembic import op
import sqlalchemy as sa


revision = "0006_scan_audit_logs"
down_revision = "0005_scan_job_target_query_text"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_job_id", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("node_name", sa.String(100), nullable=False),
        sa.Column("entry_type", sa.String(50), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_scan_audit_logs_scan_job_id"), "scan_audit_logs", ["scan_job_id"], unique=False)
    op.create_index(op.f("ix_scan_audit_logs_iteration"), "scan_audit_logs", ["iteration"], unique=False)
    op.create_index(op.f("ix_scan_audit_logs_node_name"), "scan_audit_logs", ["node_name"], unique=False)
    op.create_index(op.f("ix_scan_audit_logs_entry_type"), "scan_audit_logs", ["entry_type"], unique=False)
    op.create_index(op.f("ix_scan_audit_logs_created_at"), "scan_audit_logs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_audit_logs_created_at"), table_name="scan_audit_logs")
    op.drop_index(op.f("ix_scan_audit_logs_entry_type"), table_name="scan_audit_logs")
    op.drop_index(op.f("ix_scan_audit_logs_node_name"), table_name="scan_audit_logs")
    op.drop_index(op.f("ix_scan_audit_logs_iteration"), table_name="scan_audit_logs")
    op.drop_index(op.f("ix_scan_audit_logs_scan_job_id"), table_name="scan_audit_logs")
    op.drop_table("scan_audit_logs")
