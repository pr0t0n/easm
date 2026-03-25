"""add last_run_at to scheduled_scans

Revision ID: 0002_scheduled_scans_last_run_at
Revises: 0001_initial_schema
Create Date: 2026-03-25
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_scheduled_scans_last_run_at"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scheduled_scans",
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scheduled_scans", "last_run_at")
