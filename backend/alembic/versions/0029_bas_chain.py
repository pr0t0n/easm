"""BasSchedule.chain_key/stop_on_failure: named ordered attack chains with real stop-on-failure dispatch

Revision ID: 0029
Revises: 0028
"""
from alembic import op
import sqlalchemy as sa


revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bas_schedules", sa.Column("chain_key", sa.String(60), nullable=True))
    op.add_column("bas_schedules", sa.Column("stop_on_failure", sa.Boolean, nullable=False, server_default=sa.false()))
    op.create_index("ix_bas_schedules_chain_key", "bas_schedules", ["chain_key"])


def downgrade() -> None:
    op.drop_index("ix_bas_schedules_chain_key", table_name="bas_schedules")
    op.drop_column("bas_schedules", "stop_on_failure")
    op.drop_column("bas_schedules", "chain_key")
