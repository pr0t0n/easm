"""add last_error column to scan_jobs

Revision ID: 0010_scan_job_last_error
Revises: 0009_scan_job_retry_columns
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_scan_job_last_error"
down_revision = "0009_scan_job_retry_columns"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scan_jobs", sa.Column("last_error", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("scan_jobs", "last_error")
