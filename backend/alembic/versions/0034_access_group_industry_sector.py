"""AccessGroup.industry_sector: operator-declared sector for the real
Wavestone Cyber Benchmark 2026 external reference (see
app/services/external_benchmarks.py).

Revision ID: 0034
Revises: 0033
"""
from alembic import op
import sqlalchemy as sa


revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("access_groups", sa.Column("industry_sector", sa.String(40), nullable=True))


def downgrade() -> None:
    op.drop_column("access_groups", "industry_sector")
