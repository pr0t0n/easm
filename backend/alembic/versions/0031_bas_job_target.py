"""BasJob.target: per-job target (list-of-targets / CIDR-range dispatch)

Revision ID: 0031
Revises: 0030
"""
from alembic import op
import sqlalchemy as sa


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bas_jobs", sa.Column("target", sa.String(255), nullable=True))
    op.create_index("ix_bas_jobs_target", "bas_jobs", ["target"])


def downgrade() -> None:
    op.drop_index("ix_bas_jobs_target", table_name="bas_jobs")
    op.drop_column("bas_jobs", "target")
