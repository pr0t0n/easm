"""add retry columns to scan_jobs

Revision ID: 0009_scan_job_retry_columns
Revises: 0008_learning_report_fields
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_scan_job_retry_columns"
down_revision = "0008_learning_report_fields"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scan_jobs", sa.Column("retry_attempt", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scan_jobs", sa.Column("retry_max", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scan_jobs", sa.Column("next_retry_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("scan_jobs", "next_retry_at")
    op.drop_column("scan_jobs", "retry_max")
    op.drop_column("scan_jobs", "retry_attempt")
