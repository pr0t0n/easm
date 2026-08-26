"""BasAgent.local_network_cidr: agent self-reported real network CIDR

Revision ID: 0032
Revises: 0031
"""
from alembic import op
import sqlalchemy as sa


revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bas_agents", sa.Column("local_network_cidr", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("bas_agents", "local_network_cidr")
