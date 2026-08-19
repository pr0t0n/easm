"""BasAgent.kind: stub vs real agent, gates whether dispatched Findings are marked simulated

Revision ID: 0028
Revises: 0027
"""
from alembic import op
import sqlalchemy as sa


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bas_agents", sa.Column("kind", sa.String(20), nullable=False, server_default="stub"))
    op.create_index("ix_bas_agents_kind", "bas_agents", ["kind"])


def downgrade() -> None:
    op.drop_index("ix_bas_agents_kind", table_name="bas_agents")
    op.drop_column("bas_agents", "kind")
