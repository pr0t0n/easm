"""add persistent scan work items

Revision ID: 0013_scan_work_items
Revises: 0012_scan_tech_stack
Create Date: 2026-05-26
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0013_scan_work_items"
down_revision = "0012_scan_tech_stack"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_work_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_job_id", sa.Integer(), nullable=False),
        sa.Column("phase_id", sa.String(length=10), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("profile", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("resource_class", sa.String(length=40), nullable=False, server_default="light"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "phase_id", "tool_name", "target", name="uq_scan_work_items_scan_phase_tool_target"),
    )
    for column in ["id", "scan_job_id", "phase_id", "target", "tool_name", "profile", "resource_class", "priority", "status", "lease_until", "created_at"]:
        op.create_index(op.f(f"ix_scan_work_items_{column}"), "scan_work_items", [column], unique=False)


def downgrade():
    op.drop_table("scan_work_items")
